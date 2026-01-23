import sys
import re
import os
import subprocess
import shutil
import logging
import time
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Simple in-memory RDAP cache to avoid hammering registries
# Key: domain, Value: (timestamp, data)
_rdap_cache: Dict[str, tuple] = {}
_RDAP_CACHE_TTL = 300  # 5 minutes - short enough for fresh data, long enough to avoid rate limits

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Error: the 'requests' package is required.")
    sys.exit(1)

def create_robust_session():
    """Create a requests session with retry logic."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

try:
    import dns.resolver
except ImportError:
    print("Error: the 'dnspython' package is required.")
    sys.exit(1)

try:
    import idna
    HAS_IDNA = True
except ImportError:
    HAS_IDNA = False
    idna = None

class DNSAnalyzer:
    """DNS analysis tool for domain records and email security."""
    
    def __init__(self):
        self.dns_timeout = 1
        self.dns_tries = 1
        self.default_resolvers = ["1.1.1.1"]
        self.resolvers = self.default_resolvers.copy()
        self.iana_rdap_map = {}
        self._fetch_iana_rdap_data()
    
    def domain_to_ascii(self, domain: str) -> str:
        """Convert Unicode domain names to ASCII using IDNA."""
        domain = domain.rstrip(".")
        if HAS_IDNA:
            try:
                import idna
                return idna.encode(domain).decode("ascii")
            except Exception:
                pass
        return domain
    
    def validate_domain(self, domain: str) -> bool:
        """Return True if domain looks like a valid domain name."""
        if not domain or domain.startswith(".") or domain.endswith(".") or domain.endswith("-"):
            return False
        
        pattern = r"^[A-Za-z0-9._-]+\.[A-Za-z0-9-]{2,}$"
        return bool(re.match(pattern, domain))
    
    def _fetch_iana_rdap_data(self):
        """Populate IANA_RDAP_MAP with TLD to RDAP endpoint mappings."""
        url = "https://data.iana.org/rdap/dns.json"
        try:
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            j = r.json()
            for svc in j.get("services", []):
                if len(svc) != 2:
                    continue
                tlds, endpoints = svc
                if tlds and endpoints:
                    for tld in tlds:
                        self.iana_rdap_map[tld.lower()] = endpoints
        except Exception as e:
            logging.error(f"Failed to fetch IANA RDAP data: {e}")
    
    def _get_tld(self, domain: str) -> str:
        """Return the top-level domain from domain in lowercase."""
        return domain.rsplit(".", 1)[-1].lower()
    
    def _dns_over_https_query(self, domain: str, record_type: str) -> List[str]:
        """Query DNS records using DNS-over-HTTPS."""
        # Use Google's DNS-over-HTTPS service (more reliable)
        url = "https://dns.google/resolve"
        
        params = {
            'name': domain,
            'type': record_type.upper()
        }
        
        try:
            response = requests.get(url, params=params, timeout=5, headers={
                'Accept': 'application/dns-json'
            })
            response.raise_for_status()
            data = response.json()
            
            # Check for successful response (0 = NOERROR)
            if data.get('Status') != 0:
                return []
            
            answers = data.get('Answer', [])
            if not answers:
                return []
            
            results = []
            for answer in answers:
                record_data = answer.get('data', '').strip()
                if not record_data:
                    continue
                
                # Handle different record types
                if record_type.upper() == 'TXT':
                    # Remove quotes from TXT records
                    record_data = record_data.strip('"')
                
                # For MX records, format is already "priority hostname"
                # For other records, just use the data as-is
                if record_data and record_data not in results:
                    results.append(record_data)
            
            return results
            
        except Exception as e:
            logging.debug(f"DNS-over-HTTPS query failed: {e}")
            return []
    
    def dns_query(self, record_type: str, domain: str) -> List[str]:
        """Query domain for record type using DNS-over-HTTPS fallback."""
        if not domain or not record_type:
            return []
        
        # Try DNS-over-HTTPS first as it works better in restricted environments
        try:
            results = self._dns_over_https_query(domain, record_type)
            if results:
                return results
        except Exception as e:
            logging.debug(f"DNS-over-HTTPS failed: {e}")
        
        # Fallback to traditional DNS if DoH fails
        for resolver_ip in self.resolvers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout * self.dns_tries
            
            try:
                answer = resolver.resolve(domain, record_type)
                return [str(rr) for rr in answer]
            except dns.resolver.NXDOMAIN:
                logging.debug(f"Domain {domain} not found for {record_type}")
                return []
            except dns.resolver.NoAnswer:
                logging.debug(f"No {record_type} records for {domain}")
                continue
            except dns.resolver.Timeout:
                logging.debug(f"Timeout querying {resolver_ip} for {domain} {record_type}")
                continue
            except Exception as e:
                logging.debug(f"DNS query error with {resolver_ip}: {e}")
                continue
        
        return []
    
    def get_basic_records(self, domain: str) -> Dict[str, List[str]]:
        """Get basic DNS records for domain (parallel for speed)."""
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SRV"]
        records = {t: [] for t in record_types}
        
        def query_type(rtype):
            return (rtype, self.dns_query(rtype, domain))
        
        with ThreadPoolExecutor(max_workers=7) as executor:
            futures = {executor.submit(query_type, t): t for t in record_types}
            for future in as_completed(futures, timeout=5):
                try:
                    rtype, result = future.result()
                    records[rtype] = result
                except:
                    pass
        
        return records
    
    def get_authoritative_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records directly from authoritative nameservers (optimized for speed)."""
        record_types = ["A", "AAAA", "MX", "TXT", "NS"]
        results = {t: [] for t in record_types}
        
        try:
            # 1. Find authoritative nameservers (quick lookup)
            ns_records = self.dns_query("NS", domain)
            if not ns_records:
                parts = domain.split(".")
                if len(parts) > 2:
                    parent = ".".join(parts[-2:])
                    ns_records = self.dns_query("NS", parent)
            
            if not ns_records:
                return results

            # 2. Use only first nameserver for speed
            ns_host = ns_records[0]
            ns_ips = self.dns_query("A", ns_host.rstrip("."))
            if not ns_ips:
                return results
                
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ns_ips
            resolver.timeout = 1
            resolver.lifetime = 1
            
            # 3. Query all record types in parallel
            def query_auth_type(rtype):
                try:
                    answer = resolver.resolve(domain, rtype)
                    return (rtype, [str(rr).strip('"') for rr in answer])
                except:
                    return (rtype, [])
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(query_auth_type, t): t for t in record_types}
                for future in as_completed(futures, timeout=3):
                    try:
                        rtype, vals = future.result()
                        results[rtype] = vals
                    except:
                        pass
                    
        except Exception as e:
            logging.error(f"Authoritative lookup failed for {domain}: {e}")
            
        return results
    
    def analyze_spf(self, domain: str) -> Dict[str, Any]:
        """Analyze SPF record for domain."""
        txt_records = self.dns_query("TXT", domain)
        
        if not txt_records:
            return {
                'status': 'error',
                'message': 'No TXT records found',
                'records': [],
                'valid_records': [],
                'spf_like': []
            }
        
        valid_spf = []
        spf_like = []
        
        for record in txt_records:
            lower_record = record.lower()
            if "v=spf1" in lower_record:
                valid_spf.append(record)
            elif "spf" in lower_record:
                spf_like.append(record)
        
        if len(valid_spf) == 0:
            status = 'error' if not spf_like else 'warning'
            message = 'No valid SPF record found'
        elif len(valid_spf) == 1:
            status = 'success'
            message = 'Valid SPF record found'
        else:
            status = 'warning'
            message = 'Multiple SPF records found (there should be only one)'
        
        return {
            'status': status,
            'message': message,
            'records': txt_records,
            'valid_records': valid_spf,
            'spf_like': spf_like
        }
    
    def analyze_dmarc(self, domain: str) -> Dict[str, Any]:
        """Analyze DMARC record for domain."""
        dmarc_records = self.dns_query("TXT", f"_dmarc.{domain}")
        
        if not dmarc_records:
            return {
                'status': 'error',
                'message': 'No DMARC record found',
                'records': [],
                'valid_records': [],
                'policy': None
            }
        
        valid_dmarc = []
        dmarc_like = []
        
        for record in dmarc_records:
            lower_record = record.lower()
            if "v=dmarc1" in lower_record:
                valid_dmarc.append(record)
            elif "dmarc" in lower_record:
                dmarc_like.append(record)
        
        if len(valid_dmarc) == 0:
            status = 'error'
            message = 'No valid DMARC record found'
            policy = None
        elif len(valid_dmarc) > 1:
            status = 'warning'
            message = 'Multiple DMARC records found (there should be only one)'
            policy = None
        else:
            record = valid_dmarc[0].lower()
            if "p=none" in record:
                status = 'warning'
                message = 'DMARC policy is set to "none" - consider strengthening'
                policy = 'none'
            elif "p=reject" in record:
                status = 'success'
                message = 'DMARC policy is set to "reject" - excellent protection'
                policy = 'reject'
            elif "p=quarantine" in record:
                status = 'success'
                message = 'DMARC policy is set to "quarantine" - good protection'
                policy = 'quarantine'
            else:
                status = 'info'
                message = 'DMARC record found'
                policy = 'unknown'
        
        return {
            'status': status,
            'message': message,
            'records': dmarc_records,
            'valid_records': valid_dmarc,
            'dmarc_like': dmarc_like,
            'policy': policy
        }
    
    def analyze_dkim(self, domain: str) -> Dict[str, Any]:
        """Check common DKIM selectors for domain (parallel for speed)."""
        selectors = ["default._domainkey", "google._domainkey", 
                    "selector1._domainkey", "selector2._domainkey"]
        
        found_selectors = {}
        
        def check_selector(selector):
            records = self.dns_query("TXT", f"{selector}.{domain}")
            if records:
                dkim_records = [r for r in records if "v=dkim1" in r.lower() or "k=" in r.lower()]
                if dkim_records:
                    return (selector, dkim_records)
            return None
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(check_selector, s): s for s in selectors}
            for future in as_completed(futures, timeout=5):
                try:
                    result = future.result()
                    if result:
                        found_selectors[result[0]] = result[1]
                except:
                    pass
        
        if found_selectors:
            status = 'success'
            message = f'Found DKIM records for {len(found_selectors)} selector(s)'
        else:
            # Use neutral status - large providers use rotating/non-public selectors
            status = 'info'
            message = 'DKIM not discoverable via common selectors (large providers use rotating selectors)'
        
        return {
            'status': status,
            'message': message,
            'selectors': found_selectors
        }
    
    def analyze_mta_sts(self, domain: str) -> Dict[str, Any]:
        """Check MTA-STS (Mail Transfer Agent Strict Transport Security) for domain."""
        mta_sts_domain = f"_mta-sts.{domain}"
        records = self.dns_query("TXT", mta_sts_domain)
        
        if not records:
            return {
                'status': 'warning',
                'message': 'No MTA-STS record found',
                'record': None,
                'mode': None
            }
        
        valid_records = [r for r in records if r.lower().startswith("v=stsv1")]
        
        if not valid_records:
            return {
                'status': 'warning', 
                'message': 'No valid MTA-STS record found',
                'record': None,
                'mode': None
            }
        
        record = valid_records[0]
        mode = None
        
        if "mode=enforce" in record.lower():
            mode = 'enforce'
            status = 'success'
            message = 'MTA-STS enforced - TLS required for mail delivery'
        elif "mode=testing" in record.lower():
            mode = 'testing'
            status = 'warning'
            message = 'MTA-STS in testing mode'
        elif "mode=none" in record.lower():
            mode = 'none'
            status = 'warning'
            message = 'MTA-STS disabled (mode=none)'
        else:
            status = 'success'
            message = 'MTA-STS record found'
        
        return {
            'status': status,
            'message': message,
            'record': record,
            'mode': mode
        }
    
    def analyze_tlsrpt(self, domain: str) -> Dict[str, Any]:
        """Check TLS-RPT (TLS Reporting) for domain."""
        tlsrpt_domain = f"_smtp._tls.{domain}"
        records = self.dns_query("TXT", tlsrpt_domain)
        
        if not records:
            return {
                'status': 'warning',
                'message': 'No TLS-RPT record found',
                'record': None,
                'rua': None
            }
        
        valid_records = [r for r in records if r.lower().startswith("v=tlsrptv1")]
        
        if not valid_records:
            return {
                'status': 'warning',
                'message': 'No valid TLS-RPT record found', 
                'record': None,
                'rua': None
            }
        
        record = valid_records[0]
        rua = None
        
        # Extract reporting URI
        import re
        rua_match = re.search(r'rua=([^;\s]+)', record, re.IGNORECASE)
        if rua_match:
            rua = rua_match.group(1)
        
        return {
            'status': 'success',
            'message': 'TLS-RPT configured - receiving TLS delivery reports',
            'record': record,
            'rua': rua
        }
    
    def analyze_caa(self, domain: str) -> Dict[str, Any]:
        """Check CAA (Certificate Authority Authorization) records for domain."""
        records = self.dns_query("CAA", domain)
        
        if not records:
            return {
                'status': 'warning',
                'message': 'No CAA records found - any CA can issue certificates',
                'records': [],
                'issuers': [],
                'has_wildcard': False,
                'has_iodef': False
            }
        
        issuers = []
        has_wildcard = False
        has_iodef = False
        
        for record in records:
            lower = record.lower()
            if 'issue ' in lower or 'issue"' in lower:
                # Extract issuer
                if 'letsencrypt' in lower:
                    issuers.append('Let\'s Encrypt')
                elif 'digicert' in lower:
                    issuers.append('DigiCert')
                elif 'sectigo' in lower or 'comodo' in lower:
                    issuers.append('Sectigo')
                elif 'globalsign' in lower:
                    issuers.append('GlobalSign')
                elif 'amazon' in lower:
                    issuers.append('Amazon')
                elif 'google' in lower:
                    issuers.append('Google Trust Services')
                else:
                    # Generic extraction
                    parts = record.split()
                    if len(parts) >= 3:
                        issuers.append(parts[-1].strip('"'))
            if 'issuewild' in lower:
                has_wildcard = True
            if 'iodef' in lower:
                has_iodef = True
        
        issuers = list(set(issuers))  # Remove duplicates
        
        return {
            'status': 'success',
            'message': f'CAA configured - only {", ".join(issuers) if issuers else "specified CAs"} can issue certificates',
            'records': records,
            'issuers': issuers,
            'has_wildcard': has_wildcard,
            'has_iodef': has_iodef
        }
    
    def analyze_bimi(self, domain: str) -> Dict[str, Any]:
        """Check BIMI (Brand Indicators for Message Identification) for domain."""
        import re
        bimi_domain = f"default._bimi.{domain}"
        records = self.dns_query("TXT", bimi_domain)
        
        if not records:
            return {
                'status': 'warning',
                'message': 'No BIMI record found',
                'record': None,
                'logo_url': None,
                'vmc_url': None
            }
        
        valid_records = [r for r in records if r.lower().startswith("v=bimi1")]
        
        if not valid_records:
            return {
                'status': 'warning',
                'message': 'No valid BIMI record found',
                'record': None,
                'logo_url': None,
                'vmc_url': None
            }
        
        record = valid_records[0]
        logo_url = None
        vmc_url = None
        
        # Extract logo URL (l=)
        logo_match = re.search(r'l=([^;\s]+)', record, re.IGNORECASE)
        if logo_match:
            logo_url = logo_match.group(1)
        
        # Extract VMC certificate URL (a=)
        vmc_match = re.search(r'a=([^;\s]+)', record, re.IGNORECASE)
        if vmc_match:
            vmc_url = vmc_match.group(1)
        
        status = 'success'
        if vmc_url:
            message = 'BIMI configured with VMC certificate - brand logo will display in supported email clients'
        elif logo_url:
            message = 'BIMI configured - brand logo available (VMC recommended for Gmail)'
        else:
            status = 'warning'
            message = 'BIMI record found but missing logo URL'
        
        return {
            'status': status,
            'message': message,
            'record': record,
            'logo_url': logo_url,
            'vmc_url': vmc_url
        }
    
    def analyze_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC status for domain by looking for DNSKEY and DS records."""
        has_dnskey = False
        has_ds = False
        dnskey_records = []
        ds_records = []
        algorithm_names = {
            5: 'RSA/SHA-1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSA/SHA-256', 
            10: 'RSA/SHA-512', 13: 'ECDSA P-256/SHA-256', 14: 'ECDSA P-384/SHA-384',
            15: 'Ed25519', 16: 'Ed448'
        }
        
        # Check for DNSKEY records (at the domain itself)
        try:
            dnskey_result = self.dns_query("DNSKEY", domain)
            if dnskey_result:
                has_dnskey = True
                for rec in dnskey_result[:3]:  # Limit display
                    dnskey_records.append(rec[:100] + '...' if len(rec) > 100 else rec)
        except Exception:
            pass
        
        # Check for DS records (at parent zone - indicates delegation is signed)
        try:
            ds_result = self.dns_query("DS", domain)
            if ds_result:
                has_ds = True
                for rec in ds_result[:3]:
                    ds_records.append(rec)
        except Exception:
            pass
        
        # Determine algorithm from DS if available
        algorithm = None
        algorithm_name = None
        if ds_records:
            try:
                parts = ds_records[0].split()
                if len(parts) >= 2:
                    alg_num = int(parts[1])
                    algorithm = alg_num
                    algorithm_name = algorithm_names.get(alg_num, f'Algorithm {alg_num}')
            except:
                pass
        
        if has_dnskey and has_ds:
            return {
                'status': 'success',
                'message': 'DNSSEC fully configured - DNS responses are cryptographically signed and verified',
                'has_dnskey': True,
                'has_ds': True,
                'dnskey_records': dnskey_records,
                'ds_records': ds_records,
                'algorithm': algorithm,
                'algorithm_name': algorithm_name,
                'chain_of_trust': 'complete'
            }
        elif has_dnskey and not has_ds:
            return {
                'status': 'warning',
                'message': 'DNSSEC partially configured - DNSKEY exists but DS record missing at registrar',
                'has_dnskey': True,
                'has_ds': False,
                'dnskey_records': dnskey_records,
                'ds_records': [],
                'algorithm': None,
                'algorithm_name': None,
                'chain_of_trust': 'broken'
            }
        else:
            return {
                'status': 'warning',
                'message': 'DNSSEC not configured - DNS responses are unsigned',
                'has_dnskey': False,
                'has_ds': False,
                'dnskey_records': [],
                'ds_records': [],
                'algorithm': None,
                'algorithm_name': None,
                'chain_of_trust': 'none'
            }
    
    def analyze_ns_delegation(self, domain: str) -> Dict[str, Any]:
        """Check NS delegation by comparing child NS records with parent zone delegation."""
        # Get NS records from resolvers (what the domain says)
        child_ns = []
        parent_ns = []
        
        try:
            child_result = self.dns_query("NS", domain)
            if child_result:
                child_ns = sorted([ns.rstrip('.').lower() for ns in child_result])
        except Exception:
            pass
        
        # Get parent zone and query for delegation
        parts = domain.split('.')
        if len(parts) >= 2:
            parent_zone = '.'.join(parts[1:]) if len(parts) > 2 else parts[-1]
            
            # Try to get NS from parent by querying authoritative servers for parent
            try:
                # Query the parent zone's NS directly
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.resolvers
                resolver.timeout = self.dns_timeout
                resolver.lifetime = self.dns_timeout * 2
                
                # Get parent NS servers
                parent_ns_servers = resolver.resolve(parent_zone, 'NS')
                if parent_ns_servers:
                    # Query one of the parent's NS for the child's delegation
                    parent_server = str(parent_ns_servers[0]).rstrip('.')
                    try:
                        parent_ip = resolver.resolve(parent_server, 'A')
                        if parent_ip:
                            parent_resolver = dns.resolver.Resolver()
                            parent_resolver.nameservers = [str(parent_ip[0])]
                            parent_resolver.timeout = self.dns_timeout
                            parent_resolver.lifetime = self.dns_timeout * 2
                            
                            delegation = parent_resolver.resolve(domain, 'NS')
                            parent_ns = sorted([str(ns).rstrip('.').lower() for ns in delegation])
                    except Exception:
                        pass
            except Exception:
                pass
        
        if not child_ns:
            return {
                'status': 'error',
                'message': 'Could not retrieve NS records',
                'child_ns': [],
                'parent_ns': [],
                'match': False,
                'delegation_ok': False
            }
        
        if not parent_ns:
            # Couldn't verify parent, but child NS exists
            return {
                'status': 'success',
                'message': f'{len(child_ns)} nameserver(s) configured',
                'child_ns': child_ns,
                'parent_ns': [],
                'match': None,
                'delegation_ok': True,
                'note': 'Parent zone delegation could not be verified'
            }
        
        # Compare child and parent NS
        match = set(child_ns) == set(parent_ns)
        
        if match:
            return {
                'status': 'success',
                'message': f'NS delegation verified - {len(child_ns)} nameserver(s) match parent zone',
                'child_ns': child_ns,
                'parent_ns': parent_ns,
                'match': True,
                'delegation_ok': True
            }
        else:
            return {
                'status': 'warning',
                'message': 'NS delegation mismatch - child and parent zone have different NS records',
                'child_ns': child_ns,
                'parent_ns': parent_ns,
                'match': False,
                'delegation_ok': False,
                'note': 'This may indicate a recent change still propagating'
            }

    def get_registrar_info(self, domain: str) -> Dict[str, Any]:
        """Get registrar information via RDAP (primary) with WHOIS (backup)."""
        logging.info(f"[REGISTRAR] Getting registrar info for {domain}")
        
        # TRY RDAP FIRST - it's the primary, authoritative source
        rdap_result = None
        try:
            logging.info(f"[REGISTRAR] Trying RDAP first (primary source)...")
            rdap_data = self._rdap_lookup(domain)
            if rdap_data:
                registrar_name = self._extract_registrar_from_rdap(rdap_data)
                logging.info(f"[REGISTRAR] RDAP extracted registrar: {registrar_name}")
                if registrar_name and not registrar_name.isdigit():
                    registrant_name = self._extract_registrant_from_rdap(rdap_data)
                    reg_str = registrar_name
                    if registrant_name:
                        reg_str += f" (Registrant: {registrant_name})"
                    logging.info(f"[REGISTRAR] SUCCESS via RDAP: {reg_str}")
                    return {'status': 'success', 'source': 'RDAP', 'registrar': reg_str}
                else:
                    logging.warning(f"[REGISTRAR] RDAP data found but no valid registrar name")
            else:
                logging.warning(f"[REGISTRAR] RDAP returned no data")
        except Exception as e:
            logging.warning(f"[REGISTRAR] RDAP failed: {e}")
        
        # RDAP failed - fall back to WHOIS (backup source)
        logging.info(f"[REGISTRAR] RDAP failed, trying WHOIS as backup...")
        try:
            whois_result = self._whois_lookup_registrar(domain)
            if whois_result:
                logging.info(f"[REGISTRAR] SUCCESS via WHOIS (backup): {whois_result}")
                return {'status': 'success', 'source': 'WHOIS', 'registrar': whois_result}
        except Exception as e:
            logging.warning(f"[REGISTRAR] WHOIS failed: {e}")
        
        logging.warning(f"[REGISTRAR] FAILED - No registrar info found for {domain}")
        return {
            'status': 'error',
            'source': None,
            'registrar': None,
            'message': 'No registrar information found'
        }
    
    def _rdap_lookup(self, domain: str) -> Dict:
        """Return RDAP JSON data for domain using whodap library with retry."""
        import whodap
        
        global _rdap_cache
        
        # Check cache first to avoid hammering registries
        cache_key = domain.lower()
        if cache_key in _rdap_cache:
            cached_time, cached_data = _rdap_cache[cache_key]
            age = time.time() - cached_time
            if age < _RDAP_CACHE_TTL:
                logging.warning(f"[RDAP] Using cached data for {domain} (age: {age:.0f}s)")
                return cached_data
        
        tld = self._get_tld(domain)
        domain_name = domain.rsplit('.', 1)[0] if '.' in domain else domain
        
        logging.warning(f"[RDAP] whodap lookup: domain={domain_name}, tld={tld}")
        
        # Try whodap with retry on rate limit
        for attempt in range(2):
            try:
                response = whodap.lookup_domain(domain=domain_name, tld=tld)
                data = response.to_dict()
                logging.warning(f"[RDAP] whodap SUCCESS - got {len(data)} keys")
                # Cache the result
                _rdap_cache[cache_key] = (time.time(), data)
                return data
            except Exception as e:
                error_str = str(e).lower()
                logging.warning(f"[RDAP] whodap attempt {attempt+1} FAILED: {type(e).__name__}: {e}")
                if 'rate' in error_str or '429' in error_str:
                    if attempt == 0:
                        logging.warning("[RDAP] Rate limited, waiting 2s before retry...")
                        time.sleep(2)
                        continue
                break
        
        # Fallback to direct requests if whodap fails
        logging.warning("[RDAP] Falling back to direct requests")
        headers = {
            'Accept': 'application/rdap+json',
            'User-Agent': 'DNS-Analyzer/1.0'
        }
        
        direct_endpoints = {
            'com': 'https://rdap.verisign.com/com/v1/',
            'net': 'https://rdap.verisign.com/net/v1/',
            'org': 'https://rdap.publicinterestregistry.net/rdap/',
            'io': 'https://rdap.nic.io/',
            'tech': 'https://rdap.centralnic.com/tech/',
            'dev': 'https://rdap.nic.google/',
            'app': 'https://rdap.nic.google/',
        }
        
        endpoint = direct_endpoints.get(tld, 'https://rdap.org/')
        url = f"{endpoint.rstrip('/')}/domain/{domain}"
        
        try:
            logging.warning(f"[RDAP] Direct request to: {url}")
            resp = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
            logging.warning(f"[RDAP] Direct request status: {resp.status_code}")
            if resp.status_code < 400:
                data = resp.json()
                if "errorCode" not in data:
                    logging.warning(f"[RDAP] Direct request SUCCESS - got {len(data)} keys")
                    # Cache the result
                    _rdap_cache[cache_key] = (time.time(), data)
                    return data
                else:
                    logging.warning(f"[RDAP] Direct request returned error: {data.get('errorCode')}")
            elif resp.status_code == 429:
                logging.warning("[RDAP] Direct request also rate limited (429)")
        except Exception as e:
            logging.warning(f"[RDAP] Direct request FAILED: {type(e).__name__}: {e}")
        
        return {}
    
    def _extract_registrar_from_rdap(self, rdap_data: Dict) -> Optional[str]:
        """Extract registrar name from RDAP data."""
        entities = rdap_data.get("entities", [])
        if not entities:
            return None
            
        def find_registrar(entity_list):
            for entity in entity_list:
                roles = [r.lower() for r in entity.get("roles", [])]
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) == 2 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if len(item) >= 4 and item[0] == "fn":
                                return item[3]
                    name = entity.get("name") or entity.get("handle")
                    if name and not name.isdigit():
                        return name
                
                # Check nested entities recursively
                sub = entity.get("entities", [])
                if sub:
                    res = find_registrar(sub)
                    if res:
                        return res
            return None
            
        # First pass: direct check
        result = find_registrar(entities)
        if result:
            return result
            
        # Second pass: check notices or links if no registrar entity found
        links = rdap_data.get("links", [])
        for link in links:
            if link.get("rel") == "related" and "registrar" in link.get("href", "").lower():
                # Extract potential name from title
                title = link.get("title", "")
                if "Registrar" in title:
                    return title.replace("URL of", "").replace("RDAP Record", "").strip()

        return None

    def _extract_registrant_from_rdap(self, rdap_data: Dict) -> Optional[str]:
        """Extract registrant name from RDAP data."""
        entities = rdap_data.get("entities", [])
        if not entities:
            return None
            
        def find_registrant(entity_list):
            for entity in entity_list:
                roles = [r.lower() for r in entity.get("roles", [])]
                if "registrant" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) == 2 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if len(item) >= 4 and item[0] == "fn":
                                val = item[3]
                                if val and val.lower() not in ["redacted", "data protected", "not disclosed", "withheld"]:
                                    return val
                
                sub = entity.get("entities", [])
                if sub:
                    res = find_registrant(sub)
                    if res:
                        return res
            return None
            
        return find_registrant(entities)

    def _whois_lookup_registrar(self, domain: str) -> Optional[str]:
        """Return registrar name using direct socket WHOIS query (port 43)."""
        import socket
        
        tld = self._get_tld(domain)
        
        # Map TLDs to their WHOIS servers
        whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'io': 'whois.nic.io',
            'tech': 'whois.nic.tech',
            'dev': 'whois.nic.google',
            'app': 'whois.nic.google',
            'co': 'whois.nic.co',
            'me': 'whois.nic.me',
            'biz': 'whois.biz',
            'uk': 'whois.nic.uk',
            'de': 'whois.denic.de',
        }
        
        server = whois_servers.get(tld)
        if not server:
            logging.warning(f"[WHOIS] No server for TLD: {tld}")
            return None
        
        try:
            logging.info(f"[WHOIS] Socket query to {server} for {domain}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((server, 43))
            sock.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
            sock.close()
            
            output = response.decode('utf-8', errors='ignore')
            logging.info(f"[WHOIS] Got {len(output)} bytes from {server}")
            
            registrar = None
            registrant = None
            
            # Parse registrar
            registrar_match = re.search(r"(?i)^(?:registrar|sponsoring registrar|registrar name)\s*:\s*(.+)$", output, re.MULTILINE)
            if registrar_match:
                val = registrar_match.group(1).strip()
                if val and not val.lower().startswith('http') and val.lower() != 'not available':
                    registrar = val
            
            # Parse registrant
            registrant_match = re.search(r"(?i)^(?:registrant organization|registrant name|registrant)\s*:\s*(.+)$", output, re.MULTILINE)
            if registrant_match:
                val = registrant_match.group(1).strip()
                if val and val.lower() not in ["redacted", "data protected", "not disclosed", "withheld"]:
                    registrant = val
            
            if registrar and registrant:
                return f"{registrar} (Registrant: {registrant})"
            return registrar or registrant
            
        except Exception as e:
            logging.error(f"[WHOIS] Socket error for {domain}: {e}")
            return None
    
    def get_hosting_info(self, domain: str, results: Dict) -> Dict[str, str]:
        """Identify hosting, DNS, and email providers."""
        hosting = "Unknown"
        dns_hosting = "Standard"
        email_hosting = "Unknown"
        
        # 1. Detect DNS Hosting from NS records
        ns_records = results.get('basic_records', {}).get('NS', [])
        ns_str = " ".join(ns_records).lower()
        
        dns_providers = {
            'cloudflare': 'Cloudflare',
            'awsdns': 'Amazon Route 53',
            'route53': 'Amazon Route 53',
            'googledomains': 'Google Domains',
            'google': 'Google Cloud DNS',
            'azure-dns': 'Azure DNS',
            'digitalocean': 'DigitalOcean',
            'linode': 'Linode',
            'namesilo': 'NameSilo',
            'namecheap': 'Namecheap',
            'godaddy': 'GoDaddy',
            'domaincontrol.com': 'GoDaddy',
            'bluehost': 'Bluehost',
            'hostgator': 'HostGator',
            'registrar-servers': 'Namecheap',
            'porkbun': 'Porkbun',
            'dreamhost': 'DreamHost',
            'wixdns': 'Wix',
            'wordpress': 'WordPress',
            'squarespace': 'Squarespace'
        }
        
        for key, name in dns_providers.items():
            if key in ns_str:
                dns_hosting = name
                break

        # 2. Detect Web Hosting from A records
        a_records = results.get('basic_records', {}).get('A', [])
        if a_records:
            ip = a_records[0]
            if ip.startswith(('104.16.', '104.17.', '104.18.', '172.64.', '172.67.', '108.162.', '190.93.', '197.234.', '198.41.')):
                hosting = "Cloudflare"
            elif ip.startswith(('34.', '35.', '104.196.')):
                hosting = "Google Cloud"
            elif ip.startswith(('3.', '13.', '15.', '18.', '52.', '54.')):
                hosting = "AWS / Amazon"
            elif dns_hosting != "Standard":
                hosting = dns_hosting
        
        # 3. Detect Email Hosting from MX records
        mx_records = results.get('basic_records', {}).get('MX', [])
        mx_str = " ".join(mx_records).lower()
        
        email_providers = {
            'google': 'Google Workspace',
            'googlemail': 'Google Workspace',
            'gmail': 'Google Workspace',
            'outlook': 'Microsoft 365',
            'microsoft': 'Microsoft 365',
            'protection.outlook': 'Microsoft 365',
            'pphosted': 'Proofpoint',
            'mimecast': 'Mimecast',
            'barracuda': 'Barracuda',
            'zoho': 'Zoho Mail',
            'mailgun': 'Mailgun',
            'sendgrid': 'SendGrid',
            'amazonses': 'Amazon SES',
            'yahoodns': 'Yahoo Mail',
            'icloud': 'iCloud Mail',
            'fastmail': 'Fastmail',
            'protonmail': 'ProtonMail',
            'privateemail': 'Namecheap Email',
            'secureserver': 'GoDaddy Email',
            'hover': 'Hover',
            'hostgator': 'HostGator',
            'bluehost': 'Bluehost',
            'dreamhost': 'DreamHost',
            'mx.cloudflare': 'Cloudflare Email',
        }
        
        for key, name in email_providers.items():
            if key in mx_str:
                email_hosting = name
                break
        
        # If no match but MX exists, show first MX server
        if email_hosting == "Unknown" and mx_records:
            first_mx = mx_records[0].split()[-1] if mx_records else ""
            if first_mx:
                # Clean up and shorten
                parts = first_mx.rstrip('.').split('.')
                if len(parts) >= 2:
                    email_hosting = '.'.join(parts[-2:]).title()
        
        return {
            'hosting': hosting,
            'dns_hosting': dns_hosting,
            'email_hosting': email_hosting
        }

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Perform complete DNS analysis of domain with parallel lookups for speed."""
        
        # Run all lookups in parallel for speed (5-10s target)
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = {
                executor.submit(self.get_basic_records, domain): 'basic',
                executor.submit(self.get_authoritative_records, domain): 'auth',
                executor.submit(self.analyze_spf, domain): 'spf',
                executor.submit(self.analyze_dmarc, domain): 'dmarc',
                executor.submit(self.analyze_dkim, domain): 'dkim',
                executor.submit(self.analyze_mta_sts, domain): 'mta_sts',
                executor.submit(self.analyze_tlsrpt, domain): 'tlsrpt',
                executor.submit(self.analyze_bimi, domain): 'bimi',
                executor.submit(self.analyze_caa, domain): 'caa',
                executor.submit(self.analyze_dnssec, domain): 'dnssec',
                executor.submit(self.analyze_ns_delegation, domain): 'ns_delegation',
                executor.submit(self.get_registrar_info, domain): 'registrar',
            }
            
            results_map = {}
            for future in as_completed(futures, timeout=15):
                key = futures[future]
                try:
                    results_map[key] = future.result()
                except Exception as e:
                    logging.error(f"Error in {key} lookup: {e}")
                    results_map[key] = {} if key in ['basic', 'auth'] else {'status': 'error'}
        
        basic = results_map.get('basic', {})
        auth = results_map.get('auth', {})
        
        # Determine propagation status
        propagation_status = {}
        for rtype in basic.keys():
            b_set = set(basic.get(rtype, []))
            a_set = set(auth.get(rtype, []))
            
            if not a_set:
                status = "unknown"
            elif b_set == a_set:
                status = "synchronized"
            else:
                status = "propagating"
            
            propagation_status[rtype] = {
                'status': status,
                'synced': status == "synchronized",
                'mismatch': status == "propagating"
            }

        results = {
            'basic_records': basic,
            'authoritative_records': auth,
            'propagation_status': propagation_status,
            'spf_analysis': results_map.get('spf', {'status': 'error'}),
            'dmarc_analysis': results_map.get('dmarc', {'status': 'error'}),
            'dkim_analysis': results_map.get('dkim', {'status': 'error'}),
            'mta_sts_analysis': results_map.get('mta_sts', {'status': 'warning'}),
            'tlsrpt_analysis': results_map.get('tlsrpt', {'status': 'warning'}),
            'bimi_analysis': results_map.get('bimi', {'status': 'warning'}),
            'caa_analysis': results_map.get('caa', {'status': 'warning'}),
            'dnssec_analysis': results_map.get('dnssec', {'status': 'warning'}),
            'ns_delegation_analysis': results_map.get('ns_delegation', {'status': 'warning'}),
            'registrar_info': results_map.get('registrar', {'status': 'error', 'registrar': None})
        }
        
        # Add Hosting/Who summary
        results['hosting_summary'] = self.get_hosting_info(domain, results)
        
        # Calculate Posture Score
        results['posture'] = self._calculate_posture(results)
        
        return results
    
    def _calculate_posture(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall DNS & Trust Posture based on security controls."""
        issues = []  # Critical problems that need action
        monitoring_items = []  # Controls in monitoring/non-enforce mode
        configured_items = []  # Runtime-dependent controls that are present
        absent_items = []  # Optional controls not configured
        
        # Check DMARC policy (DNS-verifiable enforcement level)
        dmarc = results.get('dmarc_analysis', {})
        dmarc_policy = dmarc.get('policy', '').lower()
        if dmarc.get('status') != 'success':
            issues.append('No DMARC policy (email can be spoofed)')
        elif dmarc_policy == 'none':
            monitoring_items.append('DMARC in monitoring mode (p=none) - spoofed mail may still deliver')
        elif dmarc_policy == 'quarantine':
            monitoring_items.append('DMARC quarantine (p=reject recommended for full enforcement)')
        
        # Check SPF
        spf = results.get('spf_analysis', {})
        if spf.get('status') != 'success':
            issues.append('No SPF record (no sender verification)')
        
        # Check DNSSEC (DNS-verifiable)
        # Note: Unsigned DNSSEC is a deliberate design choice for many large operators
        # (Apple, Google, CDNs) who secure at other layers. Only broken chain is an issue.
        dnssec = results.get('dnssec_analysis', {})
        chain = dnssec.get('chain_of_trust', 'none')
        if chain == 'broken':
            issues.append('DNSSEC chain incomplete (DS record missing at registrar)')
        elif dnssec.get('status') == 'success':
            configured_items.append('DNSSEC (DNS responses signed)')
        else:
            # Unsigned is tracked as "not configured" - a design choice, not an error
            absent_items.append('DNSSEC (DNS response signing)')
        
        # Check NS delegation
        ns_del = results.get('ns_delegation_analysis', {})
        if ns_del.get('delegation_ok') == False:
            issues.append('NS delegation issue (DNS may not resolve correctly)')
        
        # Check CAA (DNS-verifiable)
        caa = results.get('caa_analysis', {})
        if caa.get('status') != 'success':
            issues.append('No CAA record (any CA can issue SSL certificates)')
        
        # Check MTA-STS (runtime-dependent - record presence only)
        mta_sts = results.get('mta_sts_analysis', {})
        if mta_sts.get('status') == 'success':
            configured_items.append('MTA-STS (policy present)')
        else:
            absent_items.append('MTA-STS (email TLS policy)')
        
        # Check TLS-RPT (runtime-dependent - record presence only)
        tls_rpt = results.get('tlsrpt_analysis', {})  # Note: key is 'tlsrpt_analysis' not 'tls_rpt_analysis'
        if tls_rpt.get('status') == 'success':
            configured_items.append('TLS-RPT (reporting configured)')
        else:
            absent_items.append('TLS-RPT (TLS delivery reporting)')
        
        # Check BIMI (runtime-dependent - record presence only)
        bimi = results.get('bimi_analysis', {})
        if bimi.get('status') == 'success':
            configured_items.append('BIMI (brand logo configured)')
        else:
            absent_items.append('BIMI (brand logo in inboxes)')
        
        # Determine posture state (based only on issues and monitoring - not absent optional items)
        if not issues and not monitoring_items:
            state = 'SECURE'
            color = 'success'
            icon = 'shield-alt'
            message = 'All critical DNS security controls are enforced.'
        elif not issues and monitoring_items:
            state = 'SECURE (Monitoring)'
            color = 'info'
            icon = 'eye'
            message = 'Security controls present but some are in monitoring/reporting mode.'
        elif len(issues) <= 2:
            state = 'PARTIAL'
            color = 'warning'
            icon = 'exclamation-triangle'
            message = 'Some critical security controls are missing.'
        else:
            state = 'AT RISK'
            color = 'danger'
            icon = 'times-circle'
            message = 'Critical security gaps detected. Domain may be vulnerable to spoofing or tampering.'
        
        # Generate verdicts for each section
        verdicts = self._generate_verdicts(results)
        
        return {
            'state': state,
            'color': color,
            'icon': icon,
            'message': message,
            'issues': issues,
            'configured': configured_items,
            'absent': absent_items,
            'monitoring': monitoring_items,
            'verdicts': verdicts
        }
    
    def _generate_verdicts(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Generate verdict sentences for each security section."""
        verdicts = {}
        
        # Email Security verdict
        # Key insight: DMARC enforcement is the final authority, not DKIM discoverability
        # Large providers (Google, Microsoft) use rotating DKIM selectors that aren't discoverable
        # but their DMARC=reject policy still blocks spoofing effectively
        spf_ok = results.get('spf_analysis', {}).get('status') == 'success'
        dmarc = results.get('dmarc_analysis', {})
        dmarc_ok = dmarc.get('status') == 'success'
        dmarc_policy = dmarc.get('policy', '').lower()
        dmarc_reject = dmarc_policy == 'reject'
        dmarc_quarantine = dmarc_policy == 'quarantine'
        dkim_ok = results.get('dkim_analysis', {}).get('status') == 'success'
        
        # DMARC=reject + SPF valid = No impersonation, regardless of DKIM discoverability
        if spf_ok and dmarc_ok and dmarc_reject:
            verdicts['email'] = 'DMARC policy is reject - spoofed messages will be blocked by receiving servers.'
            verdicts['email_answer'] = 'No'
        elif spf_ok and dmarc_ok and dmarc_quarantine:
            verdicts['email'] = 'DMARC policy is quarantine - spoofed messages will be flagged as spam.'
            verdicts['email_answer'] = 'Mostly No'
        elif spf_ok and dmarc_ok and dmarc_policy == 'none':
            verdicts['email'] = 'Mail authentication is configured but DMARC is in monitoring mode - spoofed mail may still be delivered.'
            verdicts['email_answer'] = 'Mostly No'
        elif spf_ok or dmarc_ok:
            verdicts['email'] = 'Partial email authentication configured - some spoofed messages may be delivered.'
            verdicts['email_answer'] = 'Partially'
        else:
            verdicts['email'] = 'No email authentication - this domain can be easily impersonated.'
            verdicts['email_answer'] = 'Yes'
        
        # Brand Security verdict
        bimi_ok = results.get('bimi_analysis', {}).get('status') == 'success'
        caa_ok = results.get('caa_analysis', {}).get('status') == 'success'
        
        if bimi_ok and caa_ok:
            verdicts['brand'] = 'Attackers cannot easily spoof your logo or obtain fraudulent TLS certificates.'
            verdicts['brand_secure'] = True
        elif caa_ok:
            verdicts['brand'] = 'Certificate issuance is controlled but brand logo (BIMI) is not configured.'
            verdicts['brand_secure'] = True
        elif bimi_ok:
            verdicts['brand'] = 'Brand logo is configured but any CA can issue certificates for this domain.'
            verdicts['brand_secure'] = False
        else:
            verdicts['brand'] = 'No brand protection controls - attackers could obtain certificates or impersonate visually.'
            verdicts['brand_secure'] = False
        
        # Domain Security verdict
        dnssec_ok = results.get('dnssec_analysis', {}).get('status') == 'success'
        ns_ok = results.get('ns_delegation_analysis', {}).get('delegation_ok', False)
        
        if dnssec_ok and ns_ok:
            verdicts['domain'] = 'DNS responses are authenticated from the root downward. Delegation is verified.'
            verdicts['domain_answer'] = 'No'
        elif dnssec_ok:
            verdicts['domain'] = 'DNS responses are signed but delegation verification had issues.'
            verdicts['domain_answer'] = 'Mostly No'
        elif ns_ok:
            verdicts['domain'] = 'Delegation is verified but DNS responses are unsigned and could be spoofed.'
            verdicts['domain_answer'] = 'Partially'
        else:
            verdicts['domain'] = 'DNS responses are unsigned and delegation may have issues.'
            verdicts['domain_answer'] = 'Yes'
        
        return verdicts
