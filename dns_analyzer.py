import sys
import re
import os
import subprocess
import shutil
import logging
import time
import socket
import ssl
import smtplib
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from datetime import datetime

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
        """Analyze SPF record for domain with deep correctness checks.
        
        Checks for:
        - Multiple SPF records (hard fail condition)
        - DNS lookup count (limit 10)
        - Permissiveness score (+all, ~all, ?all, -all)
        - Mechanism breakdown
        """
        txt_records = self.dns_query("TXT", domain)
        
        base_result = {
            'status': 'error',
            'message': 'No TXT records found',
            'records': [],
            'valid_records': [],
            'spf_like': [],
            'lookup_count': 0,
            'lookup_mechanisms': [],
            'permissiveness': None,
            'all_mechanism': None,
            'issues': [],
            'includes': []
        }
        
        if not txt_records:
            return base_result
        
        valid_spf = []
        spf_like = []
        
        for record in txt_records:
            if not record:
                continue
            lower_record = record.lower()
            if "v=spf1" in lower_record:
                valid_spf.append(record)
            elif "spf" in lower_record:
                spf_like.append(record)
        
        issues = []
        lookup_count = 0
        lookup_mechanisms = []
        permissiveness = None
        all_mechanism = None
        includes = []
        
        # Multiple SPF records is a hard fail per RFC 7208
        if len(valid_spf) > 1:
            status = 'error'
            message = 'Multiple SPF records found - this causes SPF to fail (RFC 7208)'
            issues.append('Multiple SPF records (hard fail)')
        elif len(valid_spf) == 0:
            status = 'error' if not spf_like else 'warning'
            message = 'No valid SPF record found'
        else:
            # Parse the single valid SPF record
            spf_record = valid_spf[0]
            spf_lower = spf_record.lower()
            
            # Count DNS lookup mechanisms (limit is 10)
            # Mechanisms that cause DNS lookups: include, a, mx, ptr, exists, redirect
            import re
            
            # Find all include mechanisms
            include_matches = re.findall(r'include:([^\s]+)', spf_lower)
            includes = include_matches
            lookup_count += len(include_matches)
            for inc in include_matches:
                lookup_mechanisms.append(f'include:{inc}')
            
            # Count other lookup mechanisms
            a_matches = re.findall(r'\ba[:/]', spf_lower)
            lookup_count += len(a_matches)
            if a_matches:
                lookup_mechanisms.append('a mechanism')
            
            mx_matches = re.findall(r'\bmx[:/\s]', spf_lower)
            lookup_count += len(mx_matches)
            if mx_matches:
                lookup_mechanisms.append('mx mechanism')
            
            ptr_matches = re.findall(r'\bptr[:/\s]', spf_lower)
            lookup_count += len(ptr_matches)
            if ptr_matches:
                lookup_mechanisms.append('ptr mechanism (deprecated)')
                issues.append('PTR mechanism used (deprecated, slow)')
            
            exists_matches = re.findall(r'exists:', spf_lower)
            lookup_count += len(exists_matches)
            if exists_matches:
                lookup_mechanisms.append('exists mechanism')
            
            redirect_match = re.search(r'redirect=([^\s]+)', spf_lower)
            if redirect_match:
                lookup_count += 1
                lookup_mechanisms.append(f'redirect:{redirect_match.group(1)}')
            
            # Check for 'all' mechanism and its qualifier
            all_match = re.search(r'([+\-~?]?)all\b', spf_lower)
            if all_match:
                qualifier = all_match.group(1) or '+'  # Default is pass
                all_mechanism = qualifier + 'all'
                
                if qualifier == '+' or qualifier == '':
                    permissiveness = 'DANGEROUS'
                    issues.append('+all allows anyone to send as your domain')
                elif qualifier == '?':
                    permissiveness = 'NEUTRAL'
                    issues.append('?all provides no protection')
                elif qualifier == '~':
                    permissiveness = 'SOFT'
                elif qualifier == '-':
                    permissiveness = 'STRICT'
            
            # Check lookup limit
            if lookup_count > 10:
                issues.append(f'Exceeds 10 DNS lookup limit ({lookup_count} lookups)')
                status = 'warning'
                message = f'SPF exceeds lookup limit ({lookup_count}/10 lookups)'
            elif lookup_count == 10:
                status = 'warning'
                message = 'SPF at lookup limit (10/10 lookups) - no room for growth'
                issues.append('At lookup limit (10/10)')
            elif permissiveness == 'DANGEROUS':
                status = 'error'
                message = 'SPF uses +all - anyone can send as this domain'
            elif permissiveness == 'NEUTRAL':
                status = 'warning'
                message = 'SPF uses ?all - provides no protection'
            else:
                status = 'success'
                if permissiveness == 'STRICT':
                    message = f'SPF valid with strict enforcement (-all), {lookup_count}/10 lookups'
                elif permissiveness == 'SOFT':
                    message = f'SPF valid with soft fail (~all), {lookup_count}/10 lookups'
                else:
                    message = f'SPF valid, {lookup_count}/10 lookups'
        
        return {
            'status': status,
            'message': message,
            'records': txt_records,
            'valid_records': valid_spf,
            'spf_like': spf_like,
            'lookup_count': lookup_count,
            'lookup_mechanisms': lookup_mechanisms,
            'permissiveness': permissiveness,
            'all_mechanism': all_mechanism,
            'issues': issues,
            'includes': includes
        }
    
    def analyze_dmarc(self, domain: str) -> Dict[str, Any]:
        """Analyze DMARC record for domain with deep checks.
        
        Checks for:
        - Policy (p=none/quarantine/reject)
        - Subdomain policy (sp=)
        - Percentage (pct=) - partial enforcement
        - Alignment (aspf/adkim - strict/relaxed)
        - Reporting addresses (rua/ruf)
        """
        import re
        dmarc_records = self.dns_query("TXT", f"_dmarc.{domain}")
        
        base_result = {
            'status': 'error',
            'message': 'No DMARC record found',
            'records': [],
            'valid_records': [],
            'policy': None,
            'subdomain_policy': None,
            'pct': 100,
            'aspf': 'relaxed',
            'adkim': 'relaxed',
            'rua': None,
            'ruf': None,
            'issues': []
        }
        
        if not dmarc_records:
            return base_result
        
        valid_dmarc = []
        dmarc_like = []
        
        for record in dmarc_records:
            if not record:
                continue
            lower_record = record.lower()
            if "v=dmarc1" in lower_record:
                valid_dmarc.append(record)
            elif "dmarc" in lower_record:
                dmarc_like.append(record)
        
        issues = []
        policy = None
        subdomain_policy = None
        pct = 100
        aspf = 'relaxed'
        adkim = 'relaxed'
        rua = None
        ruf = None
        
        if len(valid_dmarc) == 0:
            status = 'error'
            message = 'No valid DMARC record found'
        elif len(valid_dmarc) > 1:
            status = 'warning'
            message = 'Multiple DMARC records found (there should be only one)'
            issues.append('Multiple DMARC records')
        else:
            record = valid_dmarc[0]
            record_lower = record.lower()
            
            # Extract policy
            p_match = re.search(r'\bp=(\w+)', record_lower)
            if p_match:
                policy = p_match.group(1)
            
            # Extract subdomain policy
            sp_match = re.search(r'\bsp=(\w+)', record_lower)
            if sp_match:
                subdomain_policy = sp_match.group(1)
            
            # Extract percentage
            pct_match = re.search(r'\bpct=(\d+)', record_lower)
            if pct_match:
                pct = int(pct_match.group(1))
            
            # Extract alignment settings
            aspf_match = re.search(r'\baspf=([rs])', record_lower)
            if aspf_match:
                aspf = 'strict' if aspf_match.group(1) == 's' else 'relaxed'
            
            adkim_match = re.search(r'\badkim=([rs])', record_lower)
            if adkim_match:
                adkim = 'strict' if adkim_match.group(1) == 's' else 'relaxed'
            
            # Extract reporting addresses
            rua_match = re.search(r'\brua=([^;\s]+)', record, re.IGNORECASE)
            if rua_match:
                rua = rua_match.group(1)
            
            ruf_match = re.search(r'\bruf=([^;\s]+)', record, re.IGNORECASE)
            if ruf_match:
                ruf = ruf_match.group(1)
            
            # Build status and message
            if policy == 'none':
                status = 'warning'
                message = 'DMARC in monitoring mode (p=none) - no spoofing protection'
                issues.append('Policy p=none provides no protection')
            elif policy == 'reject':
                if pct < 100:
                    status = 'warning'
                    message = f'DMARC reject but only {pct}% enforced - partial protection'
                    issues.append(f'Only {pct}% of mail subject to policy')
                else:
                    status = 'success'
                    message = 'DMARC policy reject (100%) - excellent protection'
            elif policy == 'quarantine':
                if pct < 100:
                    status = 'warning'
                    message = f'DMARC quarantine but only {pct}% enforced - partial protection'
                    issues.append(f'Only {pct}% of mail subject to policy')
                else:
                    status = 'success'
                    message = 'DMARC policy quarantine (100%) - good protection'
            else:
                status = 'info'
                message = 'DMARC record found but policy unclear'
            
            # Check for subdomain policy mismatch
            if policy in ('reject', 'quarantine') and subdomain_policy == 'none':
                issues.append(f'Subdomains unprotected (sp=none while p={policy})')
            
            # Note about forensic reporting
            if ruf:
                issues.append('Forensic reports (ruf) configured - many providers ignore these')
        
        return {
            'status': status,
            'message': message,
            'records': dmarc_records,
            'valid_records': valid_dmarc,
            'dmarc_like': dmarc_like,
            'policy': policy,
            'subdomain_policy': subdomain_policy,
            'pct': pct,
            'aspf': aspf,
            'adkim': adkim,
            'rua': rua,
            'ruf': ruf,
            'issues': issues
        }
    
    def analyze_dkim(self, domain: str) -> Dict[str, Any]:
        """Check common DKIM selectors for domain with key quality analysis.
        
        Checks for:
        - Selector discovery
        - Key length (1024-bit = weak, 2048+ = strong)
        - Key type (rsa vs ed25519)
        - Revoked keys (p= empty)
        """
        import re
        import base64
        
        selectors = ["default._domainkey", "google._domainkey", 
                    "selector1._domainkey", "selector2._domainkey"]
        
        found_selectors = {}
        key_issues = []
        key_strengths = []
        
        def check_selector(selector):
            records = self.dns_query("TXT", f"{selector}.{domain}")
            if records:
                dkim_records = [r for r in records if "v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower()]
                if dkim_records:
                    return (selector, dkim_records)
            return None
        
        def analyze_dkim_key(record):
            """Analyze DKIM key for strength and issues."""
            key_info = {'key_type': 'rsa', 'key_bits': None, 'revoked': False, 'issues': []}
            record_lower = record.lower()
            
            # Check key type
            k_match = re.search(r'\bk=(\w+)', record_lower)
            if k_match:
                key_info['key_type'] = k_match.group(1)
            
            # Check for revoked key (empty p=)
            p_match = re.search(r'\bp=([^;\s]*)', record)
            if p_match:
                public_key = p_match.group(1)
                if not public_key or public_key.strip() == '':
                    key_info['revoked'] = True
                    key_info['issues'].append('Key revoked (p= empty)')
                else:
                    # Estimate key size from base64 length
                    # RSA key in DKIM is SubjectPublicKeyInfo format
                    # Base64 encoded, so length * 6 / 8 = bytes
                    try:
                        key_bytes = len(base64.b64decode(public_key + '=='))
                        # RSA key overhead is ~38 bytes for SPKI wrapper
                        # Actual key modulus is roughly key_bytes - 38
                        if key_bytes <= 140:  # ~1024 bit key
                            key_info['key_bits'] = 1024
                            key_info['issues'].append('1024-bit key (weak, upgrade to 2048)')
                        elif key_bytes <= 300:  # ~2048 bit key
                            key_info['key_bits'] = 2048
                        elif key_bytes <= 600:  # ~4096 bit key
                            key_info['key_bits'] = 4096
                        else:
                            key_info['key_bits'] = key_bytes * 8 // 10  # rough estimate
                    except:
                        pass
            
            return key_info
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(check_selector, s): s for s in selectors}
            for future in as_completed(futures, timeout=5):
                try:
                    result = future.result()
                    if result:
                        selector_name, records = result
                        # Analyze keys for this selector
                        selector_info = {
                            'records': records,
                            'key_info': []
                        }
                        for rec in records:
                            key_analysis = analyze_dkim_key(rec)
                            selector_info['key_info'].append(key_analysis)
                            key_issues.extend(key_analysis['issues'])
                            if key_analysis['key_bits'] and key_analysis['key_bits'] >= 2048:
                                key_strengths.append(f"{key_analysis['key_bits']}-bit")
                        found_selectors[selector_name] = selector_info
                except:
                    pass
        
        if found_selectors:
            # Check for any weak keys
            has_weak_key = any('1024-bit' in issue for issue in key_issues)
            has_revoked = any('revoked' in issue for issue in key_issues)
            
            if has_revoked:
                status = 'warning'
                message = f'Found {len(found_selectors)} DKIM selector(s) but some keys are revoked'
            elif has_weak_key:
                status = 'warning'
                message = f'Found {len(found_selectors)} DKIM selector(s) with weak key(s) (1024-bit)'
            else:
                status = 'success'
                if key_strengths:
                    message = f'Found DKIM for {len(found_selectors)} selector(s) with strong keys ({", ".join(set(key_strengths))})'
                else:
                    message = f'Found DKIM records for {len(found_selectors)} selector(s)'
        else:
            # Use neutral status - large providers use rotating/non-public selectors
            status = 'info'
            message = 'DKIM not discoverable via common selectors (large providers use rotating selectors)'
        
        return {
            'status': status,
            'message': message,
            'selectors': found_selectors,
            'key_issues': key_issues,
            'key_strengths': list(set(key_strengths))
        }
    
    def analyze_mta_sts(self, domain: str) -> Dict[str, Any]:
        """Check MTA-STS (Mail Transfer Agent Strict Transport Security) for domain.
        
        Enhanced to fetch and validate the actual policy file from:
        https://mta-sts.{domain}/.well-known/mta-sts.txt
        """
        mta_sts_domain = f"_mta-sts.{domain}"
        records = self.dns_query("TXT", mta_sts_domain)
        
        base_result = {
            'status': 'warning',
            'message': 'No MTA-STS record found',
            'record': None,
            'mode': None,
            'policy': None,
            'policy_mode': None,
            'policy_max_age': None,
            'policy_mx': [],
            'policy_fetched': False,
            'policy_error': None
        }
        
        if not records:
            return base_result
        
        valid_records = [r for r in records if r.lower().startswith("v=stsv1")]
        
        if not valid_records:
            base_result['message'] = 'No valid MTA-STS record found'
            return base_result
        
        record = valid_records[0]
        dns_id = None
        
        # Extract ID from DNS record
        import re
        id_match = re.search(r'id=([^;\s]+)', record, re.IGNORECASE)
        if id_match:
            dns_id = id_match.group(1)
        
        # Now fetch the actual policy file
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        policy_data = self._fetch_mta_sts_policy(policy_url)
        
        # Determine mode and status
        mode = policy_data.get('mode') if policy_data.get('fetched') else None
        
        if policy_data.get('fetched') and mode:
            if mode == 'enforce':
                status = 'success'
                mx_list = policy_data.get('mx', [])
                if mx_list:
                    message = f'MTA-STS enforced - TLS required for {len(mx_list)} mail server(s)'
                else:
                    message = 'MTA-STS enforced - TLS required for mail delivery'
            elif mode == 'testing':
                status = 'warning'
                message = 'MTA-STS in testing mode - TLS failures reported but not enforced'
            elif mode == 'none':
                status = 'warning'
                message = 'MTA-STS policy disabled (mode=none)'
            else:
                status = 'success'
                message = 'MTA-STS policy found'
        elif policy_data.get('error'):
            status = 'warning'
            message = f'MTA-STS DNS record found but policy file inaccessible'
        else:
            status = 'success'
            message = 'MTA-STS record found'
        
        return {
            'status': status,
            'message': message,
            'record': record,
            'dns_id': dns_id,
            'mode': mode,
            'policy': policy_data.get('raw'),
            'policy_mode': policy_data.get('mode'),
            'policy_max_age': policy_data.get('max_age'),
            'policy_mx': policy_data.get('mx', []),
            'policy_fetched': policy_data.get('fetched', False),
            'policy_error': policy_data.get('error')
        }
    
    def _fetch_mta_sts_policy(self, url: str) -> Dict[str, Any]:
        """Fetch and parse MTA-STS policy file from the well-known URL."""
        import re
        result = {
            'fetched': False,
            'raw': None,
            'mode': None,
            'max_age': None,
            'mx': [],
            'error': None
        }
        
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                policy_text = response.text
                result['fetched'] = True
                result['raw'] = policy_text
                
                # Parse policy fields (case-insensitive per RFC 8461)
                for line in policy_text.split('\n'):
                    line = line.strip()
                    line_lower = line.lower()
                    if line_lower.startswith('version:'):
                        pass  # We just check it exists
                    elif line_lower.startswith('mode:'):
                        result['mode'] = line.split(':', 1)[1].strip().lower()
                    elif line_lower.startswith('max_age:'):
                        try:
                            result['max_age'] = int(line.split(':', 1)[1].strip())
                        except ValueError:
                            pass
                    elif line_lower.startswith('mx:'):
                        mx_pattern = line.split(':', 1)[1].strip()
                        if mx_pattern:
                            result['mx'].append(mx_pattern)
            else:
                result['error'] = f'HTTP {response.status_code}'
        except requests.exceptions.SSLError:
            result['error'] = 'SSL certificate error'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection failed'
        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)[:50]
        
        return result
    
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
        
        # Build informative message with wildcard details
        message_parts = ['CAA configured']
        if issuers:
            message_parts.append(f'- only {", ".join(issuers)} can issue certificates')
        else:
            message_parts.append('- specific CAs authorized')
        
        # Explicitly mention wildcard permissions
        if has_wildcard:
            message_parts.append('(including wildcards)')
        
        return {
            'status': 'success',
            'message': ' '.join(message_parts),
            'records': records,
            'issuers': issuers,
            'has_wildcard': has_wildcard,
            'has_iodef': has_iodef
        }
    
    def analyze_bimi(self, domain: str) -> Dict[str, Any]:
        """Check BIMI (Brand Indicators for Message Identification) for domain.
        
        Enhanced to validate SVG accessibility and check VMC certificate.
        """
        import re
        bimi_domain = f"default._bimi.{domain}"
        records = self.dns_query("TXT", bimi_domain)
        
        base_result = {
            'status': 'warning',
            'message': 'No BIMI record found',
            'record': None,
            'logo_url': None,
            'vmc_url': None,
            'logo_valid': None,
            'logo_format': None,
            'logo_error': None,
            'vmc_valid': None,
            'vmc_issuer': None,
            'vmc_subject': None,
            'vmc_error': None
        }
        
        if not records:
            return base_result
        
        valid_records = [r for r in records if r.lower().startswith("v=bimi1")]
        
        if not valid_records:
            base_result['message'] = 'No valid BIMI record found'
            return base_result
        
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
        
        # Validate logo SVG
        logo_data = self._validate_bimi_logo(logo_url) if logo_url else {}
        
        # Validate VMC certificate
        vmc_data = self._validate_bimi_vmc(vmc_url) if vmc_url else {}
        
        # Build result with validation info
        status = 'success'
        message_parts = []
        
        if vmc_url and vmc_data.get('valid'):
            message_parts.append('BIMI with VMC certificate')
            if vmc_data.get('issuer'):
                message_parts.append(f"(from {vmc_data.get('issuer')})")
        elif vmc_url:
            message_parts.append('BIMI with VMC')
            if vmc_data.get('error'):
                status = 'warning'
                message_parts.append(f"- VMC issue: {vmc_data.get('error')}")
        elif logo_url:
            message_parts.append('BIMI configured')
            if logo_data.get('valid'):
                message_parts.append('- logo validated')
            message_parts.append('(VMC recommended for Gmail)')
        else:
            status = 'warning'
            message_parts.append('BIMI record found but missing logo URL')
        
        if logo_url and not logo_data.get('valid') and logo_data.get('error'):
            status = 'warning'
            message_parts.append(f"Logo issue: {logo_data.get('error')}")
        
        return {
            'status': status,
            'message': ' '.join(message_parts),
            'record': record,
            'logo_url': logo_url,
            'vmc_url': vmc_url,
            'logo_valid': logo_data.get('valid'),
            'logo_format': logo_data.get('format'),
            'logo_error': logo_data.get('error'),
            'vmc_valid': vmc_data.get('valid'),
            'vmc_issuer': vmc_data.get('issuer'),
            'vmc_subject': vmc_data.get('subject'),
            'vmc_error': vmc_data.get('error')
        }
    
    def _validate_bimi_logo(self, url: str) -> Dict[str, Any]:
        """Validate BIMI logo SVG accessibility and basic format."""
        result = {'valid': False, 'format': None, 'error': None}
        
        if not url:
            result['error'] = 'No URL'
            return result
        
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'svg' in content_type.lower():
                    result['valid'] = True
                    result['format'] = 'SVG'
                elif 'image' in content_type.lower():
                    result['valid'] = True
                    result['format'] = content_type.split('/')[-1].upper()
                else:
                    # Try GET to check content
                    get_resp = requests.get(url, timeout=5, allow_redirects=True)
                    if get_resp.status_code == 200:
                        content = get_resp.text[:500].lower()
                        if '<svg' in content:
                            result['valid'] = True
                            result['format'] = 'SVG'
                        else:
                            result['error'] = 'Not SVG format'
                    else:
                        result['error'] = f'HTTP {get_resp.status_code}'
            else:
                result['error'] = f'HTTP {response.status_code}'
        except requests.exceptions.SSLError:
            result['error'] = 'SSL error'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection failed'
        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)[:30]
        
        return result
    
    def _validate_bimi_vmc(self, url: str) -> Dict[str, Any]:
        """Validate BIMI VMC (Verified Mark Certificate) accessibility."""
        result = {'valid': False, 'issuer': None, 'subject': None, 'error': None}
        
        if not url:
            result['error'] = 'No URL'
            return result
        
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                content = response.text
                # VMC is a PEM-encoded certificate
                if '-----BEGIN CERTIFICATE-----' in content:
                    result['valid'] = True
                    # Try to extract issuer from common VMC issuers
                    if 'DigiCert' in content:
                        result['issuer'] = 'DigiCert'
                    elif 'Entrust' in content:
                        result['issuer'] = 'Entrust'
                    elif 'GlobalSign' in content:
                        result['issuer'] = 'GlobalSign'
                    else:
                        result['issuer'] = 'Verified CA'
                else:
                    result['error'] = 'Invalid certificate format'
            else:
                result['error'] = f'HTTP {response.status_code}'
        except requests.exceptions.SSLError:
            result['error'] = 'SSL error'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection failed'
        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)[:30]
        
        return result
    
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
                child_ns = sorted([ns.rstrip('.').lower() for ns in child_result if ns])
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
                            parent_ns = sorted([str(ns).rstrip('.').lower() for ns in delegation if ns])
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
        ns_str = " ".join(r for r in ns_records if r).lower()
        
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
        mx_str = " ".join(r for r in mx_records if r).lower()
        
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
        
        # Early check: Does domain exist / is it delegated?
        domain_exists = True
        domain_status = 'active'
        domain_status_message = None
        
        try:
            # Check for ANY record - if NXDOMAIN, domain doesn't exist
            self.resolver.resolve(domain, 'SOA')
        except dns.resolver.NXDOMAIN:
            domain_exists = False
            domain_status = 'nxdomain'
            domain_status_message = 'Domain does not exist (NXDOMAIN). No DNS records found at any level.'
        except dns.resolver.NoAnswer:
            # Domain exists but no SOA - check NS
            try:
                self.resolver.resolve(domain, 'NS')
            except dns.resolver.NXDOMAIN:
                domain_exists = False
                domain_status = 'nxdomain'
                domain_status_message = 'Domain does not exist (NXDOMAIN).'
            except dns.resolver.NoAnswer:
                # No NS either - likely undelegated
                domain_status = 'undelegated'
                domain_status_message = 'Domain may not be delegated - no NS records found.'
            except Exception:
                pass
        except dns.resolver.NoNameservers:
            domain_status = 'no_nameservers'
            domain_status_message = 'No nameservers responding for this domain. Zone may be misconfigured or undelegated.'
        except Exception:
            pass  # Continue with analysis
        
        # If domain clearly doesn't exist, return early with minimal results
        if not domain_exists:
            return {
                'domain_exists': False,
                'domain_status': domain_status,
                'domain_status_message': domain_status_message,
                'basic_records': {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [], 'CNAME': [], 'SOA': []},
                'authoritative_records': {},
                'propagation_status': {},
                'spf_analysis': {'status': 'n/a', 'message': 'Domain does not exist'},
                'dmarc_analysis': {'status': 'n/a', 'message': 'Domain does not exist'},
                'dkim_analysis': {'status': 'n/a'},
                'mta_sts_analysis': {'status': 'n/a'},
                'tlsrpt_analysis': {'status': 'n/a'},
                'bimi_analysis': {'status': 'n/a'},
                'caa_analysis': {'status': 'n/a'},
                'dnssec_analysis': {'status': 'n/a'},
                'ns_delegation_analysis': {'status': 'error', 'delegation_ok': False, 'message': 'Domain does not exist'},
                'registrar_info': {'status': 'n/a', 'registrar': None},
                'smtp_transport': None,
                'hosting_summary': {'hosting': 'N/A', 'dns_hosting': 'N/A', 'email_hosting': 'N/A'},
                'posture': {
                    'score': 0,
                    'grade': 'N/A',
                    'label': 'Non-existent Domain',
                    'issues': ['Domain does not exist or is not delegated'],
                    'color': 'secondary'
                }
            }
        
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
            try:
                for future in as_completed(futures, timeout=20):
                    key = futures[future]
                    try:
                        results_map[key] = future.result()
                    except Exception as e:
                        logging.error(f"Error in {key} lookup: {e}")
                        results_map[key] = {} if key in ['basic', 'auth'] else {'status': 'error'}
            except FuturesTimeoutError:
                # Some futures timed out - continue with what we have
                logging.warning(f"Some lookups timed out for {domain}, continuing with partial results")
                for future, key in futures.items():
                    if key not in results_map:
                        if future.done():
                            try:
                                results_map[key] = future.result()
                            except Exception:
                                results_map[key] = {} if key in ['basic', 'auth'] else {'status': 'error'}
                        else:
                            logging.warning(f"Lookup {key} timed out for {domain}")
                            results_map[key] = {} if key in ['basic', 'auth'] else {'status': 'timeout'}
        
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
            'domain_exists': True,
            'domain_status': domain_status,
            'domain_status_message': domain_status_message,
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
        
        # SMTP Transport verification disabled - port 25 blocked in production
        results['smtp_transport'] = None
        
        # Add Hosting/Who summary
        results['hosting_summary'] = self.get_hosting_info(domain, results)
        
        # Calculate Posture Score
        results['posture'] = self._calculate_posture(results)
        
        return results
    
    def _read_smtp_response(self, sock: socket.socket, timeout: float = 2.0) -> str:
        """Read complete SMTP multi-line response with proper termination detection."""
        sock.settimeout(timeout)
        response_lines = []
        try:
            while True:
                data = sock.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    break
                response_lines.append(data)
                # SMTP multi-line response ends with "<code><space>" pattern
                # Single line responses are "<code><space>text\r\n"
                lines = ''.join(response_lines).split('\r\n')
                for line in lines:
                    if line and len(line) >= 4:
                        # Check if this is a terminating line (code followed by space)
                        if line[3:4] == ' ' or line[3:4] == '':
                            return ''.join(response_lines)
                # Safety: if we've read enough, stop
                if len(''.join(response_lines)) > 8192:
                    break
        except socket.timeout:
            pass
        return ''.join(response_lines)
    
    def verify_smtp_server(self, mx_host: str, timeout: float = 1.5) -> Dict[str, Any]:
        """
        Verify SMTP server capabilities: STARTTLS, TLS version, cipher, certificate.
        Uses raw sockets for reliable TLS information extraction.
        Optimized for speed with tight timeouts (1.5s connection, 1s response).
        """
        result = {
            'host': mx_host,
            'reachable': False,
            'starttls': False,
            'tls_version': None,
            'cipher': None,
            'cipher_bits': None,
            'certificate': None,
            'cert_valid': False,
            'cert_expiry': None,
            'cert_days_remaining': None,
            'cert_issuer': None,
            'cert_subject': None,
            'error': None
        }
        
        sock = None
        ssl_sock = None
        
        try:
            # Connect to SMTP server on port 25 using raw socket (fast 1.5s timeout)
            sock = socket.create_connection((mx_host, 25), timeout=timeout)
            result['reachable'] = True
            
            # Read banner with proper multi-line handling (fast 1s timeout)
            banner = self._read_smtp_response(sock, timeout=1.0)
            if not banner.startswith('220'):
                result['error'] = f"Unexpected banner"
                return result
            
            # Send EHLO and read full response (fast 1s timeout)
            sock.send(b'EHLO dnstool.local\r\n')
            ehlo_resp = self._read_smtp_response(sock, timeout=1.0)
            
            # Check for STARTTLS support in EHLO response
            if 'STARTTLS' in ehlo_resp.upper():
                result['starttls'] = True
                
                # Send STARTTLS command
                sock.send(b'STARTTLS\r\n')
                starttls_resp = self._read_smtp_response(sock, timeout=1.0)
                
                if starttls_resp.startswith('220'):
                    # Wrap socket with TLS
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    ssl_sock = context.wrap_socket(sock, server_hostname=mx_host)
                    
                    # Get TLS details
                    result['tls_version'] = ssl_sock.version()
                    cipher_info = ssl_sock.cipher()
                    if cipher_info:
                        result['cipher'] = cipher_info[0]
                        result['cipher_bits'] = cipher_info[2] if len(cipher_info) > 2 else None
                    
                    # Get certificate (returns empty dict with CERT_NONE, need to reconnect with validation)
                    # Try with certificate validation to get cert details
                    try:
                        ssl_sock.close()
                        sock = socket.create_connection((mx_host, 25), timeout=timeout)
                        sock.recv(1024)  # banner
                        sock.send(b'EHLO dnstool.local\r\n')
                        sock.recv(2048)
                        sock.send(b'STARTTLS\r\n')
                        sock.recv(1024)
                        
                        context_verify = ssl.create_default_context()
                        ssl_sock = context_verify.wrap_socket(sock, server_hostname=mx_host)
                        
                        result['cert_valid'] = True
                        cert = ssl_sock.getpeercert()
                        if cert:
                            result['certificate'] = True
                            
                            # Parse expiry date
                            not_after = cert.get('notAfter')
                            if not_after:
                                try:
                                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                    result['cert_expiry'] = expiry.strftime('%Y-%m-%d')
                                    days_remaining = (expiry - datetime.now()).days
                                    result['cert_days_remaining'] = days_remaining
                                except Exception:
                                    result['cert_expiry'] = not_after
                            
                            # Parse issuer
                            issuer = cert.get('issuer')
                            if issuer:
                                issuer_dict = {}
                                for item in issuer:
                                    if item and len(item) > 0:
                                        issuer_dict[item[0][0]] = item[0][1]
                                org = issuer_dict.get('organizationName', '')
                                cn = issuer_dict.get('commonName', '')
                                result['cert_issuer'] = org or cn
                            
                            # Parse subject
                            subject = cert.get('subject')
                            if subject:
                                subject_dict = {}
                                for item in subject:
                                    if item and len(item) > 0:
                                        subject_dict[item[0][0]] = item[0][1]
                                result['cert_subject'] = subject_dict.get('commonName', mx_host)
                    
                    except ssl.SSLCertVerificationError as e:
                        result['cert_valid'] = False
                        result['error'] = f"Certificate invalid: {str(e)[:100]}"
                    except Exception as e:
                        # Certificate validation failed but TLS works
                        result['cert_valid'] = False
                        result['error'] = f"Cert check failed: {str(e)[:50]}"
                else:
                    result['error'] = f"STARTTLS failed: {starttls_resp[:50]}"
            else:
                result['error'] = "STARTTLS not supported"
                
        except socket.timeout:
            result['error'] = "Connection timeout"
        except socket.gaierror as e:
            result['error'] = f"DNS resolution failed"
        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except OSError as e:
            if 'Network is unreachable' in str(e):
                result['error'] = "Network unreachable"
            else:
                result['error'] = str(e)[:50]
        except Exception as e:
            result['error'] = str(e)[:50]
        finally:
            try:
                if ssl_sock:
                    ssl_sock.close()
                elif sock:
                    sock.close()
            except Exception:
                pass
        
        return result
    
    def analyze_smtp_transport(self, domain: str, mx_records: List[str] = None) -> Dict[str, Any]:
        """
        Analyze SMTP transport security for all MX servers of a domain.
        Checks STARTTLS, TLS version, ciphers, and certificates.
        """
        result = {
            'status': 'warning',
            'message': 'SMTP transport not verified',
            'servers': [],
            'summary': {
                'total_servers': 0,
                'reachable': 0,
                'starttls_supported': 0,
                'tls_1_3': 0,
                'tls_1_2': 0,
                'valid_certs': 0,
                'expiring_soon': 0  # certs expiring in < 30 days
            },
            'issues': [],
            'mta_sts_enforced': False
        }
        
        # Get MX records if not provided
        if mx_records is None:
            mx_records = self.dns_query('MX', domain)
        
        if not mx_records:
            result['status'] = 'error'
            result['message'] = 'No MX records found'
            return result
        
        # Extract hostnames from MX records (format: "priority hostname")
        mx_hosts = []
        for mx in mx_records:
            parts = mx.split()
            if len(parts) >= 2:
                hostname = parts[1].rstrip('.')
                mx_hosts.append(hostname)
            elif len(parts) == 1:
                hostname = parts[0].rstrip('.')
                mx_hosts.append(hostname)
        
        result['summary']['total_servers'] = len(mx_hosts)
        
        # Verify each MX server (limit to first 2 to keep under 5s total)
        mx_hosts_to_check = mx_hosts[:2]
        
        # Use thread pool for parallel verification (fast 3s budget)
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {executor.submit(self.verify_smtp_server, host, 1.5): host for host in mx_hosts_to_check}
                
                try:
                    for future in as_completed(futures, timeout=3):
                        try:
                            server_result = future.result(timeout=2)
                            result['servers'].append(server_result)
                            
                            if server_result['reachable']:
                                result['summary']['reachable'] += 1
                            if server_result['starttls']:
                                result['summary']['starttls_supported'] += 1
                            if server_result['tls_version'] == 'TLSv1.3':
                                result['summary']['tls_1_3'] += 1
                            elif server_result['tls_version'] == 'TLSv1.2':
                                result['summary']['tls_1_2'] += 1
                            if server_result['cert_valid']:
                                result['summary']['valid_certs'] += 1
                            if server_result.get('cert_days_remaining') and server_result['cert_days_remaining'] < 30:
                                result['summary']['expiring_soon'] += 1
                                
                        except Exception as e:
                            logging.warning(f"SMTP verification error for {futures[future]}: {e}")
                except TimeoutError:
                    logging.warning("SMTP verification timed out - some servers not checked")
        except Exception as e:
            logging.warning(f"SMTP verification failed: {e}")
        
        # Analyze results
        total = result['summary']['total_servers']
        reachable = result['summary']['reachable']
        starttls = result['summary']['starttls_supported']
        valid_certs = result['summary']['valid_certs']
        
        if reachable == 0:
            result['status'] = 'warning'
            result['message'] = f'Port 25 check unavailable'
            result['issues'].append('SMTP port 25 may be blocked by hosting provider - this is common for cloud platforms')
        elif starttls == 0:
            result['status'] = 'error'
            result['message'] = 'No mail servers support STARTTLS'
            result['issues'].append('Mail is transmitted unencrypted - critical security issue')
        elif starttls < reachable:
            result['status'] = 'warning'
            result['message'] = f'Only {starttls}/{reachable} servers support STARTTLS'
            result['issues'].append('Some mail servers do not support encryption')
        elif valid_certs < starttls:
            result['status'] = 'warning'
            result['message'] = f'STARTTLS supported but {starttls - valid_certs} server(s) have certificate issues'
            result['issues'].append('Some certificates failed validation')
        else:
            result['status'] = 'success'
            tls_versions = []
            if result['summary']['tls_1_3'] > 0:
                tls_versions.append('TLS 1.3')
            if result['summary']['tls_1_2'] > 0:
                tls_versions.append('TLS 1.2')
            tls_str = '/'.join(tls_versions) if tls_versions else 'TLS'
            result['message'] = f'All {starttls} server(s) support encrypted transport ({tls_str})'
        
        # Check for expiring certificates
        if result['summary']['expiring_soon'] > 0:
            result['issues'].append(f'{result["summary"]["expiring_soon"]} certificate(s) expiring within 30 days')
        
        return result
    
    def _calculate_posture(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall DNS & Trust Posture based on security controls."""
        issues = []  # Critical problems that need action
        monitoring_items = []  # Controls in monitoring/non-enforce mode
        configured_items = []  # Runtime-dependent controls that are present
        absent_items = []  # Optional controls not configured
        
        # Check DMARC policy (DNS-verifiable enforcement level)
        dmarc = results.get('dmarc_analysis', {})
        dmarc_policy = (dmarc.get('policy') or '').lower()
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
        
        # Check if DNSSEC is configured (affects overall posture label)
        has_dnssec = dnssec.get('status') == 'success'
        
        # Determine posture state
        # SECURE = all controls enforced INCLUDING DNSSEC
        # STRONG = excellent email controls but no DNSSEC (valid design choice)
        # PARTIAL = some controls missing
        # AT RISK = critical gaps
        if not issues and not monitoring_items:
            if has_dnssec:
                state = 'SECURE'
                color = 'success'
                icon = 'shield-alt'
                message = 'All security controls enforced including DNSSEC.'
            else:
                state = 'STRONG'
                color = 'success'
                icon = 'check-circle'
                message = 'Email security controls enforced. DNSSEC not configured (common for large operators).'
        elif not issues and monitoring_items:
            if has_dnssec:
                state = 'SECURE (Monitoring)'
                color = 'info'
                icon = 'eye'
                message = 'Security controls present but some in monitoring mode.'
            else:
                state = 'STRONG (Monitoring)'
                color = 'info'
                icon = 'eye'
                message = 'Email controls present but some in monitoring mode. DNSSEC not configured.'
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
        dmarc_policy = (dmarc.get('policy') or '').lower()
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
