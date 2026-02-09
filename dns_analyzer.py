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

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

from dns_providers import (CNAME_PROVIDER_MAP, DANE_MX_CAPABILITY,
    DMARC_MONITORING_PROVIDERS, SPF_FLATTENING_PROVIDERS,
    DYNAMIC_SERVICES_PROVIDERS, DYNAMIC_SERVICES_ZONES, HOSTED_DKIM_PROVIDERS)
from rdap_cache import RDAPCache, _rdap_cache, _RDAP_CACHE_TTL

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
    import dns.flags
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
    
    # Multi-resolver configuration for consensus-based queries
    # Using diverse providers for triangulation and accuracy
    CONSENSUS_RESOLVERS = [
        {"name": "Cloudflare", "ip": "1.1.1.1", "doh": "https://cloudflare-dns.com/dns-query"},
        {"name": "Google", "ip": "8.8.8.8", "doh": "https://dns.google/resolve"},
        {"name": "Quad9", "ip": "9.9.9.9", "doh": None},
        {"name": "OpenDNS", "ip": "208.67.222.222", "doh": None},
    ]
    
    USER_AGENT = 'DNSTool-DomainSecurityAudit/1.0 (+https://dnstool.it-help.tech)'

    CNAME_PROVIDER_MAP = CNAME_PROVIDER_MAP

    def __init__(self):
        self.dns_timeout = 2
        self.dns_tries = 2
        self.default_resolvers = ["1.1.1.1"]
        self.resolvers = self.default_resolvers.copy()
        self.iana_rdap_map = {}
        self.consensus_enabled = True
        self._executor = ThreadPoolExecutor(max_workers=20)
        self._dns_cache: Dict[str, tuple] = {}
        self._dns_cache_lock = __import__('threading').Lock()
        self._DNS_CACHE_TTL = 30
        self._ct_cache: Dict[str, tuple] = {}
        self._ct_cache_lock = __import__('threading').Lock()
        self._CT_CACHE_TTL = 3600
        self._fetch_iana_rdap_data()

    def _dns_cache_get(self, key: str) -> Optional[List[str]]:
        """Get cached DNS result if still valid."""
        with self._dns_cache_lock:
            if key in self._dns_cache:
                ts, data = self._dns_cache[key]
                if time.time() - ts < self._DNS_CACHE_TTL:
                    return data
                del self._dns_cache[key]
        return None

    def _dns_cache_set(self, key: str, data: List[str]):
        """Cache a DNS result with TTL."""
        with self._dns_cache_lock:
            self._dns_cache[key] = (time.time(), data)
            if len(self._dns_cache) > 5000:
                cutoff = time.time() - self._DNS_CACHE_TTL
                expired = [k for k, (ts, _) in self._dns_cache.items() if ts < cutoff]
                for k in expired:
                    del self._dns_cache[k]
    
    def _get_ct_cache(self, domain: str) -> Optional[list]:
        with self._ct_cache_lock:
            key = domain.lower()
            if key in self._ct_cache:
                ts, data = self._ct_cache[key]
                if time.time() - ts < self._CT_CACHE_TTL:
                    return data
                del self._ct_cache[key]
        return None

    def _set_ct_cache(self, domain: str, data: list):
        with self._ct_cache_lock:
            self._ct_cache[domain.lower()] = (time.time(), data)
            if len(self._ct_cache) > 200:
                cutoff = time.time() - self._CT_CACHE_TTL
                expired = [k for k, (ts, _) in self._ct_cache.items() if ts < cutoff]
                for k in expired:
                    del self._ct_cache[k]

    def _find_parent_zone(self, domain: str) -> Optional[str]:
        """Find the parent zone that contains this domain by looking for NS records.
        For 'dnstool.it-help.tech', returns 'it-help.tech'.
        For 'it-help.tech', returns None (it IS the zone apex).
        """
        parts = domain.split('.')
        for i in range(1, len(parts) - 1):
            candidate = '.'.join(parts[i:])
            try:
                ns_result = self.dns_query("NS", candidate)
                if ns_result:
                    return candidate
            except Exception:
                continue
        return None

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
            r = requests.get(url, timeout=5, headers={'User-Agent': self.USER_AGENT})
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
        """Query DNS records using DNS-over-HTTPS with explicit error handling.
        
        Returns empty list for both 'record not found' and 'service unavailable'.
        Errors are logged with enough context to distinguish failure modes.
        """
        DOH_TIMEOUT = 5  # seconds
        url = "https://dns.google/resolve"
        
        params = {
            'name': domain,
            'type': record_type.upper()
        }
        
        try:
            response = requests.get(url, params=params, timeout=DOH_TIMEOUT, headers={
                'Accept': 'application/dns-json',
                'User-Agent': self.USER_AGENT
            })
            response.raise_for_status()
            data = response.json()
            
            # Check for successful response (0 = NOERROR)
            status = data.get('Status', -1)
            if status != 0:
                # NXDOMAIN=3, SERVFAIL=2, etc - these are "no data" not "service error"
                logging.debug(f"DoH {record_type} for {domain}: DNS status {status} (no data)")
                return []
            
            answers = data.get('Answer', [])
            if not answers:
                logging.debug(f"DoH {record_type} for {domain}: No answers in response")
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
        
        except requests.exceptions.Timeout:
            logging.warning(f"DoH {record_type} for {domain}: TIMEOUT ({DOH_TIMEOUT}s) - service may be slow")
            return []
        except requests.exceptions.ConnectionError as e:
            logging.warning(f"DoH {record_type} for {domain}: CONNECTION ERROR - {e}")
            return []
        except requests.exceptions.HTTPError as e:
            logging.warning(f"DoH {record_type} for {domain}: HTTP ERROR {e.response.status_code if e.response else 'unknown'}")
            return []
        except Exception as e:
            logging.debug(f"DoH {record_type} for {domain}: {type(e).__name__}: {e}")
            return []
    
    def _query_single_resolver(self, domain: str, record_type: str, resolver_ip: str) -> tuple[str, List[str], Optional[str]]:
        """Query a single resolver and return (resolver_ip, results, error)."""
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout * self.dns_tries
            
            answer = resolver.resolve(domain, record_type)
            results = sorted([str(rr) for rr in answer])  # Sort for comparison
            return (resolver_ip, results, None)
        except dns.resolver.NXDOMAIN:
            return (resolver_ip, [], "NXDOMAIN")
        except dns.resolver.NoAnswer:
            return (resolver_ip, [], "NoAnswer")
        except dns.resolver.Timeout:
            return (resolver_ip, [], "Timeout")
        except Exception as e:
            return (resolver_ip, [], str(e))
    
    def dns_query_with_consensus(self, record_type: str, domain: str) -> Dict[str, Any]:
        """Query multiple resolvers and return consensus results with discrepancy detection.
        
        Returns:
            {
                'records': List[str],  # The consensus records
                'consensus': bool,  # True if all resolvers agree
                'resolver_count': int,  # Number of resolvers that responded
                'discrepancies': List[str],  # Any discrepancies found
                'resolver_results': Dict[str, List[str]]  # Results per resolver
            }
        """
        if not domain or not record_type:
            return {
                'records': [],
                'consensus': True,
                'resolver_count': 0,
                'discrepancies': [],
                'resolver_results': {}
            }
        
        # Query all resolvers in parallel
        resolver_results = {}
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(
                    self._query_single_resolver, 
                    domain, 
                    record_type, 
                    r["ip"]
                ): r["name"] 
                for r in self.CONSENSUS_RESOLVERS
            }
            
            for future in as_completed(futures, timeout=5):
                resolver_name = futures[future]
                try:
                    resolver_ip, results, error = future.result()
                    if not error:
                        resolver_results[resolver_name] = results
                    else:
                        logging.debug(f"{resolver_name} ({resolver_ip}) returned {error} for {domain} {record_type}")
                except Exception as e:
                    logging.debug(f"Error querying {resolver_name}: {e}")
        
        # Determine consensus
        if not resolver_results:
            # All resolvers failed, fall back to DoH
            doh_results = self._dns_over_https_query(domain, record_type)
            return {
                'records': doh_results,
                'consensus': True,  # Single source, no discrepancy possible
                'resolver_count': 1 if doh_results else 0,
                'discrepancies': [],
                'resolver_results': {'DoH': doh_results} if doh_results else {}
            }
        
        # Find the most common result (majority voting)
        result_sets = [tuple(sorted(r)) for r in resolver_results.values()]
        from collections import Counter
        result_counter = Counter(result_sets)
        most_common = result_counter.most_common(1)[0][0]
        consensus_records = list(most_common)
        
        # Check for discrepancies
        discrepancies = []
        all_same = len(set(result_sets)) == 1
        
        if not all_same:
            for resolver_name, results in resolver_results.items():
                if tuple(sorted(results)) != most_common:
                    discrepancies.append(
                        f"{resolver_name} returned different results: {results}"
                    )
            logging.warning(f"DNS discrepancy for {domain} {record_type}: {discrepancies}")
        
        return {
            'records': consensus_records,
            'consensus': all_same,
            'resolver_count': len(resolver_results),
            'discrepancies': discrepancies,
            'resolver_results': resolver_results
        }
    
    def validate_resolver_consensus(self, domain: str) -> Dict[str, Any]:
        """Validate that multiple resolvers return consistent results for critical records.
        
        This is a scientific rigor check - we query multiple resolvers and report any discrepancies.
        """
        critical_types = ['A', 'MX', 'NS', 'TXT']  # Most important for security analysis
        validation_results = {
            'consensus_reached': True,
            'resolvers_queried': len(self.CONSENSUS_RESOLVERS),
            'checks_performed': 0,
            'discrepancies': [],
            'per_record_consensus': {}
        }
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            consensus_futures = {
                executor.submit(self.dns_query_with_consensus, rt, domain): rt
                for rt in critical_types
            }
            for future in as_completed(consensus_futures, timeout=8):
                record_type = consensus_futures[future]
                try:
                    consensus_result = future.result()
                    validation_results['checks_performed'] += 1
                    validation_results['per_record_consensus'][record_type] = {
                        'consensus': consensus_result['consensus'],
                        'resolver_count': consensus_result['resolver_count'],
                        'discrepancies': consensus_result['discrepancies']
                    }
                    
                    if not consensus_result['consensus']:
                        validation_results['consensus_reached'] = False
                        for disc in consensus_result['discrepancies']:
                            validation_results['discrepancies'].append(f"{record_type}: {disc}")
                except Exception as e:
                    logging.warning(f"Consensus check failed for {record_type}: {e}")
                    validation_results['per_record_consensus'][record_type] = {
                        'consensus': True,
                        'resolver_count': 0,
                        'discrepancies': [],
                        'error': str(e)
                    }
        
        return validation_results
    
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
    
    def check_dnssec_ad_flag(self, domain: str) -> Dict[str, Any]:
        """
        Check if DNS responses have the AD (Authentic Data) flag set.
        The AD flag indicates that a DNSSEC-validating resolver has verified
        the cryptographic signatures in the response chain.
        """
        result = {
            'ad_flag': False,
            'validated': False,
            'resolver_used': None,
            'error': None
        }
        
        # Use Google's public DNS (8.8.8.8) which is a validating resolver
        validating_resolvers = ['8.8.8.8', '1.1.1.1']
        
        for resolver_ip in validating_resolvers:
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 3
                resolver.lifetime = 5
                # Enable DNSSEC - request the AD flag
                resolver.use_edns(edns=0, ednsflags=dns.flags.DO)
                
                # Query for A record (or SOA as fallback)
                try:
                    answer = resolver.resolve(domain, 'A')
                except dns.resolver.NoAnswer:
                    answer = resolver.resolve(domain, 'SOA')
                
                # Check if AD flag is set in the response
                if answer.response.flags & dns.flags.AD:
                    result['ad_flag'] = True
                    result['validated'] = True
                    result['resolver_used'] = resolver_ip
                    return result
                else:
                    result['ad_flag'] = False
                    result['validated'] = False
                    result['resolver_used'] = resolver_ip
                    return result
                    
            except dns.resolver.NXDOMAIN:
                result['error'] = 'Domain not found'
                return result
            except Exception as e:
                logging.debug(f"AD flag check failed with {resolver_ip}: {e}")
                continue
        
        result['error'] = 'Could not verify AD flag'
        return result
    
    def _dns_query_with_ttl(self, record_type: str, domain: str) -> tuple:
        """Query DNS with TTL. Returns (records_list, ttl_seconds_or_None)."""
        try:
            url = "https://dns.google/resolve"
            params = {'name': domain, 'type': record_type.upper()}
            response = requests.get(url, params=params, timeout=5, headers={'Accept': 'application/dns-json', 'User-Agent': self.USER_AGENT})
            if response.status_code == 200:
                data = response.json()
                if data.get('Status', -1) != 0:
                    return ([], None)
                answers = data.get('Answer', [])
                if not answers:
                    return ([], None)
                ttl = answers[0].get('TTL')
                results = []
                for answer in answers:
                    rd = answer.get('data', '').strip()
                    if not rd:
                        continue
                    if record_type.upper() == 'TXT':
                        rd = rd.strip('"')
                    if rd and rd not in results:
                        results.append(rd)
                return (results, ttl)
        except Exception:
            pass
        for resolver_ip in self.resolvers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout * self.dns_tries
            try:
                answer = resolver.resolve(domain, record_type)
                ttl = answer.rrset.ttl if answer.rrset else None
                return ([str(rr) for rr in answer], ttl)
            except dns.resolver.NXDOMAIN:
                return ([], None)
            except (dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                continue
        return ([], None)
    
    def get_basic_records(self, domain: str) -> Dict[str, List[str]]:
        """Get basic DNS records for domain (parallel for speed)."""
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA"]
        records = {t: [] for t in record_types}
        records["SRV"] = []  # SRV needs special handling
        
        # Common SRV service prefixes to check
        srv_prefixes = [
            "_autodiscover._tcp",  # Microsoft Exchange/O365
            "_sip._tls",           # SIP/VoIP  
            "_sipfederationtls._tcp",  # Lync/Skype federation
            "_xmpp-client._tcp",   # XMPP chat (Jabber)
            "_caldavs._tcp",       # CalDAV (calendar)
            "_carddavs._tcp",      # CardDAV (contacts)
            "_imaps._tcp",         # IMAP over TLS
            "_submission._tcp",    # Email submission
        ]
        
        records['_ttl'] = {}
        
        def query_type(rtype):
            values, ttl = self._dns_query_with_ttl(rtype, domain)
            return (rtype, values, ttl)
        
        def query_srv(prefix):
            result = self.dns_query("SRV", f"{prefix}.{domain}")
            if result:
                return (prefix, result)
            return None
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            type_futures = {executor.submit(query_type, t): t for t in record_types}
            srv_futures = {executor.submit(query_srv, p): p for p in srv_prefixes}
            
            for future in as_completed(type_futures, timeout=6):
                try:
                    rtype, result, ttl = future.result()
                    records[rtype] = result
                    if ttl is not None:
                        records['_ttl'][rtype] = ttl
                except Exception:
                    pass
            
            for future in as_completed(srv_futures, timeout=6):
                try:
                    result = future.result()
                    if result:
                        prefix, srv_records = result
                        for rec in srv_records:
                            records["SRV"].append(f"{prefix}: {rec}")
                except Exception:
                    pass
        
        return records
    
    def get_authoritative_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records directly from authoritative nameservers (optimized for speed)."""
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CAA", "SOA"]
        email_subdomains = {
            'DMARC': f'_dmarc.{domain}',
            'MTA-STS': f'_mta-sts.{domain}',
            'TLS-RPT': f'_smtp._tls.{domain}',
        }
        results = {t: [] for t in record_types}
        for key in email_subdomains:
            results[key] = []
        results['_query_status'] = {}
        results['_ttl'] = {}
        
        try:
            ns_records = self.dns_query("NS", domain)
            if not ns_records:
                parts = domain.split(".")
                if len(parts) > 2:
                    parent = ".".join(parts[-2:])
                    ns_records = self.dns_query("NS", parent)
            
            if not ns_records:
                return results

            ns_host = ns_records[0]
            ns_ips = self.dns_query("A", ns_host.rstrip("."))
            if not ns_ips:
                return results
                
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ns_ips
            resolver.timeout = 2
            resolver.lifetime = 2
            
            def query_auth_type(result_key, qname=None, dns_type=None):
                try:
                    answer = resolver.resolve(qname or domain, dns_type or result_key)
                    ttl = answer.rrset.ttl if answer.rrset else None
                    return (result_key, [str(rr).strip('"') for rr in answer], 'success', ttl)
                except dns.resolver.NXDOMAIN:
                    return (result_key, [], 'nxdomain', None)
                except dns.resolver.NoAnswer:
                    return (result_key, [], 'nodata', None)
                except dns.resolver.NoNameservers:
                    return (result_key, [], 'servfail', None)
                except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                    return (result_key, [], 'timeout', None)
                except Exception:
                    return (result_key, [], 'error', None)
            
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = {}
                for t in record_types:
                    futures[executor.submit(query_auth_type, t)] = t
                for key, qname in email_subdomains.items():
                    futures[executor.submit(query_auth_type, key, qname, 'TXT')] = key
                for future in as_completed(futures, timeout=6):
                    try:
                        rtype, vals, status, ttl = future.result()
                        results[rtype] = vals
                        results['_query_status'][rtype] = status
                        if ttl is not None:
                            results['_ttl'][rtype] = ttl
                    except Exception:
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
            'includes': [],
            'no_mail_intent': False
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
        no_mail_intent = False
        
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
            
            # Check if -all is used with legitimate senders (not a no-mail domain)
            # Per RFC 7489 Section 10.1, -all may cause rejection before DMARC processing
            has_senders = len(include_matches) > 0 or a_matches or mx_matches
            if permissiveness == 'STRICT' and has_senders:
                issues.append('RFC 7489 §10.1: -all may cause rejection before DMARC evaluation, preventing DKIM from being checked')
            
            # Detect "no-mail domain" pattern: v=spf1 -all with no senders
            # This is an intentional security configuration for domains that don't send email
            no_mail_intent = False
            spf_normalized = re.sub(r'\s+', ' ', spf_lower.strip())
            if spf_normalized == 'v=spf1 -all' or spf_normalized == '"v=spf1 -all"':
                no_mail_intent = True
            
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
                if no_mail_intent:
                    message = 'Valid SPF (no mail allowed) - domain declares it sends no email'
                elif permissiveness == 'STRICT':
                    message = f'SPF valid with strict enforcement (-all), {lookup_count}/10 lookups'
                elif permissiveness == 'SOFT':
                    message = f'SPF valid with industry-standard soft fail (~all), {lookup_count}/10 lookups'
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
            'includes': includes,
            'no_mail_intent': no_mail_intent
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
        np_policy = None
        t_testing = None
        psd_flag = None
        
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
            
            # DMARCbis tag detection (draft-ietf-dmarc-dmarcbis)
            # np= : Non-existent subdomain policy — blocks spoofing via fake subdomains
            np_match = re.search(r'\bnp=(\w+)', record_lower)
            if np_match:
                np_policy = np_match.group(1)
            else:
                np_policy = None
            
            # t= : Testing mode (replaces pct= in DMARCbis)
            t_match = re.search(r'\bt=([yn])', record_lower)
            if t_match:
                t_testing = t_match.group(1)
            else:
                t_testing = None
            
            # psd= : Public Suffix Domain flag
            psd_match = re.search(r'\bpsd=([yn])', record_lower)
            if psd_match:
                psd_flag = psd_match.group(1)
            else:
                psd_flag = None
            
            # Build status and message
            if policy == 'none':
                status = 'warning'
                message = 'DMARC in monitoring mode (p=none) - spoofed mail still delivered, no enforcement'
                issues.append('Policy p=none provides no protection - spoofed emails reach inboxes')
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
            
            # DMARCbis subdomain spoofing gap: no np= and no sp= with enforcing p=
            if policy in ('reject', 'quarantine') and not np_policy and not subdomain_policy:
                issues.append('No np= tag (DMARCbis) — non-existent subdomains inherit p= policy but adding np=reject provides explicit protection against subdomain spoofing')
            
            # Note about forensic reporting
            if ruf:
                issues.append('Forensic reports (ruf) configured - many providers ignore these')
        
        dmarcbis_tags = {}
        if np_policy:
            dmarcbis_tags['np'] = np_policy
        if t_testing:
            dmarcbis_tags['t'] = t_testing
        if psd_flag:
            dmarcbis_tags['psd'] = psd_flag
        
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
            'np_policy': np_policy,
            't_testing': t_testing,
            'psd_flag': psd_flag,
            'dmarcbis_tags': dmarcbis_tags,
            'issues': issues
        }
    
    SELECTOR_PROVIDER_MAP = {
        'selector1._domainkey': 'Microsoft 365',
        'selector2._domainkey': 'Microsoft 365',
        'google._domainkey': 'Google Workspace',
        'google2048._domainkey': 'Google Workspace',
        'k1._domainkey': 'MailChimp',
        'k2._domainkey': 'MailChimp',
        'k3._domainkey': 'MailChimp',
        'mailchimp._domainkey': 'MailChimp',
        'mandrill._domainkey': 'MailChimp (Mandrill)',
        's1._domainkey': 'SendGrid',
        's2._domainkey': 'SendGrid',
        'sendgrid._domainkey': 'SendGrid',
        'mailjet._domainkey': 'Mailjet',
        'amazonses._domainkey': 'Amazon SES',
        'postmark._domainkey': 'Postmark',
        'sparkpost._domainkey': 'SparkPost',
        'mailgun._domainkey': 'Mailgun',
        'sendinblue._domainkey': 'Brevo (Sendinblue)',
        'mimecast._domainkey': 'Mimecast',
        'proofpoint._domainkey': 'Proofpoint',
        'everlytickey1._domainkey': 'Everlytic',
        'zendesk1._domainkey': 'Zendesk',
        'zendesk2._domainkey': 'Zendesk',
        'cm._domainkey': 'Campaign Monitor',
    }

    MX_TO_DKIM_PROVIDER = {
        'google': 'Google Workspace',
        'googlemail': 'Google Workspace',
        'gmail': 'Google Workspace',
        'outlook': 'Microsoft 365',
        'microsoft': 'Microsoft 365',
        'protection.outlook': 'Microsoft 365',
        'o365': 'Microsoft 365',
        'exchange': 'Microsoft 365',
        'intermedia': 'Microsoft 365',
        'pphosted': 'Proofpoint',
        'gpphosted': 'Proofpoint',
        'iphmx': 'Proofpoint',
        'mimecast': 'Mimecast',
        'barracudanetworks': 'Barracuda',
        'barracuda': 'Barracuda',
        'perception-point': 'Perception Point',
        'sophos': 'Sophos',
        'fireeyecloud': 'FireEye',
        'trendmicro': 'Trend Micro',
        'forcepoint': 'Forcepoint',
        'messagelabs': 'Symantec',
        'hornetsecurity': 'Hornetsecurity',
        'antispamcloud': 'SpamExperts',
        'spamexperts': 'SpamExperts',
        'zoho': 'Zoho Mail',
        'mailgun': 'Mailgun',
        'sendgrid': 'SendGrid',
        'amazonses': 'Amazon SES',
        'fastmail': 'Fastmail',
        'protonmail': 'ProtonMail',
        'mx.cloudflare': 'Cloudflare Email',
    }

    SECURITY_GATEWAYS = {
        'Proofpoint', 'Mimecast', 'Barracuda', 'Perception Point',
        'Sophos', 'FireEye', 'Trend Micro', 'Forcepoint',
        'Symantec', 'Hornetsecurity', 'SpamExperts',
    }

    PRIMARY_PROVIDER_SELECTORS = {
        'Microsoft 365': ['selector1._domainkey', 'selector2._domainkey'],
        'Google Workspace': ['google._domainkey', 'google2048._domainkey'],
        'Proofpoint': ['proofpoint._domainkey'],
        'Mimecast': ['mimecast._domainkey'],
        'Mailgun': ['mailgun._domainkey'],
        'SendGrid': ['s1._domainkey', 's2._domainkey', 'sendgrid._domainkey'],
        'Amazon SES': ['amazonses._domainkey'],
        'Zoho Mail': ['default._domainkey'],
        'Fastmail': ['fm1._domainkey', 'fm2._domainkey', 'fm3._domainkey'],
        'ProtonMail': ['protonmail._domainkey', 'protonmail2._domainkey', 'protonmail3._domainkey'],
        'Cloudflare Email': ['default._domainkey'],
    }

    SPF_MAILBOX_PROVIDERS = {
        'spf.protection.outlook': 'Microsoft 365',
        '_spf.google': 'Google Workspace',
        'spf.intermedia': 'Microsoft 365',
        'emg.intermedia': 'Microsoft 365',
        'zoho.com': 'Zoho Mail',
        'messagingengine.com': 'Fastmail',
        'protonmail.ch': 'ProtonMail',
        'mimecast': 'Mimecast',
        'pphosted': 'Proofpoint',
    }

    SPF_ANCILLARY_SENDERS = {
        'servers.mcsv.net': 'MailChimp',
        'spf.mandrillapp': 'MailChimp',
        'sendgrid.net': 'SendGrid',
        'amazonses.com': 'Amazon SES',
        'mailgun.org': 'Mailgun',
        'spf.sparkpostmail': 'SparkPost',
        'mail.zendesk.com': 'Zendesk',
        'spf.brevo.com': 'Brevo (Sendinblue)',
        'spf.sendinblue': 'Brevo (Sendinblue)',
        'spf.mailjet': 'Mailjet',
        'spf.postmarkapp': 'Postmark',
        'spf.mtasv.net': 'Postmark',
        'spf.freshdesk': 'Freshdesk',
    }

    DMARC_MONITORING_PROVIDERS = DMARC_MONITORING_PROVIDERS
    SPF_FLATTENING_PROVIDERS = SPF_FLATTENING_PROVIDERS
    DYNAMIC_SERVICES_PROVIDERS = DYNAMIC_SERVICES_PROVIDERS
    DYNAMIC_SERVICES_ZONES = DYNAMIC_SERVICES_ZONES
    HOSTED_DKIM_PROVIDERS = HOSTED_DKIM_PROVIDERS

    def _detect_email_security_management(self, spf_analysis: dict, dmarc_analysis: dict, tlsrpt_analysis: dict, mta_sts_analysis: dict = None, domain: str = None, dkim_analysis: dict = None) -> dict:
        """Detect email security management providers from DMARC rua/ruf, TLS-RPT rua, SPF includes, MTA-STS, Hosted DKIM, and Dynamic Services.
        
        Extracts the operational security partner network from DNS records — intelligence
        most tools ignore. Includes Dynamic Services detection (Red Sift, Mailhardener, Valimail) via
        DNS subzone delegation of email security zones (_dmarc, _domainkey, _mta-sts, _smtp._tls).
        Detects Hosted DKIM via CNAME chains on discovered DKIM selectors (Proofpoint, Mimecast, etc.).
        """
        import re
        providers = {}
        details = []

        def _extract_mailto_domains(rua_string):
            """Extract domains from rua/ruf mailto: URIs (may be comma-separated)."""
            if not rua_string:
                return []
            domains = []
            mailto_matches = re.findall(r'mailto:([^,;\s]+)', rua_string, re.IGNORECASE)
            for addr in mailto_matches:
                if '@' in addr:
                    domain = addr.split('@')[1].strip().rstrip('.')
                    domains.append(domain)
            return domains

        def _match_provider(domain):
            """Match a domain against known monitoring providers."""
            domain_lower = domain.lower()
            for pattern, info in self.DMARC_MONITORING_PROVIDERS.items():
                if domain_lower == pattern or domain_lower.endswith('.' + pattern):
                    return info
            return None

        dmarc_rua = dmarc_analysis.get('rua', '')
        dmarc_ruf = dmarc_analysis.get('ruf', '')
        dmarc_rua_domains = _extract_mailto_domains(dmarc_rua)
        dmarc_ruf_domains = _extract_mailto_domains(dmarc_ruf)

        for rua_domain in dmarc_rua_domains + dmarc_ruf_domains:
            provider = _match_provider(rua_domain)
            if provider and provider['name'] not in providers:
                source = 'DMARC forensic reports (ruf)' if rua_domain in dmarc_ruf_domains and rua_domain not in dmarc_rua_domains else 'DMARC aggregate reports (rua)'
                if rua_domain in dmarc_rua_domains and rua_domain in dmarc_ruf_domains:
                    source = 'DMARC aggregate (rua) and forensic (ruf) reports'
                providers[provider['name']] = {
                    **provider,
                    'sources': [source],
                    'detected_from': ['DMARC']
                }

        tlsrpt_rua = tlsrpt_analysis.get('rua', '')
        tlsrpt_domains = _extract_mailto_domains(tlsrpt_rua)

        for rua_domain in tlsrpt_domains:
            provider = _match_provider(rua_domain)
            if provider:
                if provider['name'] in providers:
                    if 'TLS-RPT' not in providers[provider['name']]['detected_from']:
                        providers[provider['name']]['detected_from'].append('TLS-RPT')
                        providers[provider['name']]['sources'].append('TLS-RPT delivery reports')
                else:
                    providers[provider['name']] = {
                        **provider,
                        'sources': ['TLS-RPT delivery reports'],
                        'detected_from': ['TLS-RPT']
                    }

        spf_includes = spf_analysis.get('includes', [])
        spf_flattening_detected = None

        for include in spf_includes:
            include_lower = include.lower()
            for pattern, info in self.SPF_FLATTENING_PROVIDERS.items():
                if include_lower.endswith(pattern) or pattern in include_lower:
                    spf_flattening_detected = {
                        'provider': info['name'],
                        'vendor': info['vendor'],
                        'include': include
                    }
                    if info['name'] in providers:
                        if 'SPF flattening' not in providers[info['name']]['detected_from']:
                            providers[info['name']]['detected_from'].append('SPF flattening')
                            providers[info['name']]['sources'].append(f'SPF flattening (include:{include})')
                    else:
                        providers[info['name']] = {
                            'name': info['name'],
                            'vendor': info['vendor'],
                            'capabilities': ['SPF management', 'SPF flattening'],
                            'sources': [f'SPF flattening (include:{include})'],
                            'detected_from': ['SPF flattening']
                        }
                    break

        if mta_sts_analysis and mta_sts_analysis.get('status') in ('success', 'warning') and mta_sts_analysis.get('record'):
            mta_sts_cname = mta_sts_analysis.get('hosting_cname', '')
            mta_sts_provider_found = False
            for name, prov in providers.items():
                if 'MTA-STS hosting' in prov.get('capabilities', []):
                    if 'MTA-STS' not in prov.get('detected_from', []):
                        prov['detected_from'].append('MTA-STS')
                        prov['sources'].append('MTA-STS policy hosting')
                    mta_sts_provider_found = True

            if not mta_sts_provider_found and mta_sts_cname:
                for domain_pattern, info in self.DMARC_MONITORING_PROVIDERS.items():
                    if 'MTA-STS hosting' in info.get('capabilities', []) and domain_pattern in mta_sts_cname:
                        prov_name = info['name']
                        if prov_name in providers:
                            if 'MTA-STS' not in providers[prov_name].get('detected_from', []):
                                providers[prov_name]['detected_from'].append('MTA-STS')
                                providers[prov_name]['sources'].append(f'MTA-STS hosting (CNAME: {mta_sts_cname})')
                        else:
                            providers[prov_name] = {
                                'name': prov_name,
                                'vendor': info['vendor'],
                                'capabilities': info['capabilities'],
                                'sources': [f'MTA-STS hosting (CNAME: {mta_sts_cname})'],
                                'detected_from': ['MTA-STS']
                            }
                        break

        if domain and dkim_analysis and dkim_analysis.get('selectors'):
            for sel_name, sel_data in dkim_analysis['selectors'].items():
                dkim_fqdn = f'{sel_name}.{domain}'
                try:
                    cname_answers = dns.resolver.resolve(dkim_fqdn, 'CNAME')
                    for rdata in cname_answers:
                        cname_target = str(rdata).rstrip('.').lower()
                        for cname_pattern, dkim_info in self.HOSTED_DKIM_PROVIDERS.items():
                            if cname_target.endswith(cname_pattern):
                                prov_name = dkim_info['name']
                                sel_short = sel_name.replace('._domainkey', '')
                                if prov_name in providers:
                                    if 'Hosted DKIM' not in providers[prov_name]['detected_from']:
                                        providers[prov_name]['detected_from'].append('Hosted DKIM')
                                        providers[prov_name]['sources'].append(f'Hosted DKIM (CNAME: {sel_short} → {cname_target})')
                                    if 'DKIM hosting' not in providers[prov_name].get('capabilities', []):
                                        providers[prov_name].setdefault('capabilities', []).append('DKIM hosting')
                                else:
                                    providers[prov_name] = {
                                        'name': prov_name,
                                        'vendor': dkim_info['vendor'],
                                        'capabilities': ['DKIM hosting'],
                                        'sources': [f'Hosted DKIM (CNAME: {sel_short} → {cname_target})'],
                                        'detected_from': ['Hosted DKIM'],
                                    }
                                break
                except Exception:
                    pass

        if domain:
            ds_zones = {
                '_dmarc': f'_dmarc.{domain}',
                '_domainkey': f'_domainkey.{domain}',
                '_mta-sts': f'_mta-sts.{domain}',
                '_smtp._tls': f'_smtp._tls.{domain}',
            }
            ds_detections = {}
            for zone_key, zone_fqdn in ds_zones.items():
                try:
                    ns_answers = dns.resolver.resolve(zone_fqdn, 'NS')
                    for rdata in ns_answers:
                        ns_host = str(rdata).rstrip('.').lower()
                        for ns_pattern, ds_info in self.DYNAMIC_SERVICES_PROVIDERS.items():
                            if ns_host.endswith(ns_pattern):
                                prov_name = ds_info['name']
                                cap = self.DYNAMIC_SERVICES_ZONES.get(zone_key, f'{zone_key} management')
                                if prov_name not in ds_detections:
                                    ds_detections[prov_name] = {
                                        'info': ds_info,
                                        'capabilities': [],
                                        'zones': [],
                                    }
                                if cap not in ds_detections[prov_name]['capabilities']:
                                    ds_detections[prov_name]['capabilities'].append(cap)
                                if zone_key not in ds_detections[prov_name]['zones']:
                                    ds_detections[prov_name]['zones'].append(zone_key)
                                break
                except Exception:
                    pass

            for prov_name, ds_data in ds_detections.items():
                cap_labels = ', '.join(ds_data['capabilities'])
                if prov_name in providers:
                    if 'Dynamic Services' not in providers[prov_name]['detected_from']:
                        providers[prov_name]['detected_from'].append('Dynamic Services')
                        providers[prov_name]['sources'].append(f'Dynamic Services ({cap_labels})')
                    for cap in ds_data['capabilities']:
                        if cap not in providers[prov_name].get('capabilities', []):
                            providers[prov_name].setdefault('capabilities', []).append(cap)
                else:
                    info = ds_data['info']
                    providers[prov_name] = {
                        'name': prov_name,
                        'vendor': info['vendor'],
                        'capabilities': ds_data['capabilities'],
                        'sources': [f'Dynamic Services ({cap_labels})'],
                        'detected_from': ['Dynamic Services'],
                    }

        actively_managed = len(providers) > 0
        provider_list = list(providers.values())

        return {
            'actively_managed': actively_managed,
            'providers': provider_list,
            'spf_flattening': spf_flattening_detected,
            'provider_count': len(provider_list),
        }

    def _classify_selector_provider(self, selector_name: str, primary_provider: str = None) -> str:
        """Map a DKIM selector to its known provider, or 'Unknown' if not recognized.
        
        When primary_provider is 'Unknown' (self-hosted email), generic selectors like
        selector1/selector2 are not attributed to Microsoft 365 — many self-hosted
        enterprises reuse these common selector names independently.
        """
        provider = self.SELECTOR_PROVIDER_MAP.get(selector_name, 'Unknown')
        if provider != 'Unknown' and primary_provider == 'Unknown':
            ambiguous_selectors = {
                'selector1._domainkey': 'Microsoft 365',
                'selector2._domainkey': 'Microsoft 365',
                's1._domainkey': 'SendGrid',
                's2._domainkey': 'SendGrid',
                'default._domainkey': None,
                'k1._domainkey': 'MailChimp',
                'k2._domainkey': 'MailChimp',
            }
            if selector_name in ambiguous_selectors:
                return 'Unknown'
        return provider

    def _detect_primary_mail_provider(self, mx_records: list, spf_record: str = None) -> dict:
        """Detect the primary mail platform from MX records and SPF includes for DKIM correlation.
        
        Returns a dict with:
          - provider: the platform that signs/sends mail (DKIM source)
          - gateway: the security gateway in front, if any (e.g. Proofpoint, Mimecast)
        
        Evidence hierarchy for sending platform detection:
          - SPF includes are authoritative: the domain owner explicitly declares which
            platforms are authorized to send mail on their behalf. An include for
            spf.protection.outlook.com is a definitive declaration of Microsoft 365 usage.
          - MX records show where inbound mail is delivered, which is often but not always
            the same as the sending platform.
          - When MX points to a security gateway but SPF includes a different sending
            platform, SPF is the stronger signal for DKIM attribution since DKIM is
            signed by the sending platform, not the inbound gateway.
          - When MX matches a known mailbox provider (M365, Google, etc.) and there's no
            gateway, MX and SPF typically agree — MX is used as the primary signal for
            efficiency since it's already available.
        """
        result = {'provider': 'Unknown', 'gateway': None}
        
        if not mx_records and not spf_record:
            return result
        
        mx_provider = None
        if mx_records:
            mx_str = " ".join(r for r in mx_records if r).lower()
            for key, provider in self.MX_TO_DKIM_PROVIDER.items():
                if key in mx_str:
                    mx_provider = provider
                    break
        
        spf_provider = None
        if spf_record:
            spf_lower = spf_record.lower()
            for key, provider in self.SPF_MAILBOX_PROVIDERS.items():
                if key in spf_lower:
                    spf_provider = provider
                    break
            if not spf_provider:
                for key, provider in self.SPF_ANCILLARY_SENDERS.items():
                    if key in spf_lower:
                        spf_provider = provider
                        break
        
        if mx_provider and mx_provider in self.SECURITY_GATEWAYS:
            if spf_provider and spf_provider != mx_provider:
                result['provider'] = spf_provider
                result['gateway'] = mx_provider
            else:
                result['provider'] = mx_provider
        elif mx_provider:
            result['provider'] = mx_provider
        elif spf_provider:
            result['provider'] = spf_provider
        
        return result

    def analyze_dkim(self, domain: str, mx_records: list = None, custom_selectors: list = None) -> Dict[str, Any]:
        """Check common DKIM selectors for domain with key quality analysis.
        
        Checks for:
        - Selector discovery
        - Key length (1024-bit = weak, 2048+ = strong)
        - Key type (rsa vs ed25519)
        - Revoked keys (p= empty)
        - Provider attribution per selector
        - Primary mail platform DKIM coverage
        """
        import re
        import base64
        
        # Comprehensive selector list covering major ESPs and common patterns
        selectors = [
            # Generic/common
            "default._domainkey", "dkim._domainkey", "mail._domainkey",
            "email._domainkey", "k1._domainkey", "k2._domainkey",
            "s1._domainkey", "s2._domainkey", "sig1._domainkey",
            # Microsoft 365
            "selector1._domainkey", "selector2._domainkey",
            # Google Workspace
            "google._domainkey", "google2048._domainkey",
            # Major ESPs
            "mailjet._domainkey", "mandrill._domainkey", "amazonses._domainkey",
            "sendgrid._domainkey", "mailchimp._domainkey", "postmark._domainkey",
            "sparkpost._domainkey", "mailgun._domainkey", "sendinblue._domainkey",
            # Enterprise
            "mimecast._domainkey", "proofpoint._domainkey", "everlytickey1._domainkey",
            "zendesk1._domainkey", "zendesk2._domainkey", "cm._domainkey",
            # Common patterns
            "mx._domainkey", "smtp._domainkey", "mailer._domainkey",
            # ProtonMail
            "protonmail._domainkey", "protonmail2._domainkey", "protonmail3._domainkey",
            # Fastmail
            "fm1._domainkey", "fm2._domainkey", "fm3._domainkey",
        ]
        
        if custom_selectors:
            for cs in custom_selectors:
                if cs not in selectors:
                    selectors.insert(0, cs)
        
        found_selectors = {}
        key_issues = []
        key_strengths = []
        
        def check_selector(selector):
            fqdn = f"{selector}.{domain}"
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = ['1.1.1.1', '8.8.8.8']
                resolver.timeout = 1.5
                resolver.lifetime = 2.0
                answer = resolver.resolve(fqdn, 'TXT')
                records = [str(rr).strip('"') for rr in answer]
                if records:
                    dkim_records = [r for r in records if "v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower()]
                    if dkim_records:
                        return (selector, dkim_records)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except dns.exception.Timeout:
                pass
            except Exception:
                pass
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
        
        if not mx_records:
            mx_records = self.dns_query("MX", domain) or []
        
        spf_records = self.dns_query("TXT", domain) or []
        spf_record = next((r for r in spf_records if r.lower().startswith("v=spf1")), None)
        
        provider_info = self._detect_primary_mail_provider(mx_records, spf_record)
        primary_provider = provider_info['provider']
        security_gateway = provider_info['gateway']
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_selector, s): s for s in selectors}
            for future in as_completed(futures, timeout=10):
                try:
                    result = future.result()
                    if result:
                        selector_name, records = result
                        provider = self._classify_selector_provider(selector_name, primary_provider)
                        selector_info = {
                            'records': records,
                            'key_info': [],
                            'provider': provider,
                            'user_hint': bool(custom_selectors and selector_name in custom_selectors)
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
        
        found_providers = set()
        for sel_name, sel_data in found_selectors.items():
            p = sel_data.get('provider', 'Unknown')
            if p != 'Unknown':
                found_providers.add(p)
        
        primary_has_dkim = False
        primary_dkim_note = ''
        unattributed_selectors = [
            sel_name for sel_name, sel_data in found_selectors.items()
            if sel_data.get('provider', 'Unknown') == 'Unknown'
        ]
        if primary_provider != 'Unknown':
            expected_selectors = self.PRIMARY_PROVIDER_SELECTORS.get(primary_provider, [])
            if expected_selectors:
                primary_has_dkim = any(s in found_selectors for s in expected_selectors)
            else:
                primary_has_dkim = primary_provider in found_providers
            if not primary_has_dkim and unattributed_selectors:
                primary_has_dkim = True
                for sel_name in unattributed_selectors:
                    found_selectors[sel_name]['provider'] = primary_provider
                    found_selectors[sel_name]['inferred'] = True
                found_providers.add(primary_provider)
                inferred_names = ', '.join(s.replace('._domainkey', '') for s in unattributed_selectors)
                primary_dkim_note = (
                    f'DKIM selector(s) {inferred_names} inferred as {primary_provider} '
                    f'(custom selector names — not the standard {primary_provider} selector).'
                )
        
        third_party_only = False
        if found_selectors and primary_provider != 'Unknown' and not primary_has_dkim:
            third_party_names = ', '.join(sorted(found_providers)) if found_providers else 'third-party services'
            third_party_only = True
            primary_dkim_note = (
                f'DKIM verified for {third_party_names} only \u2014 '
                f'no DKIM found for primary mail platform ({primary_provider}). '
                f'The primary provider may use custom selectors not discoverable through standard checks.'
            )
        
        if found_selectors:
            has_weak_key = any('1024-bit' in issue for issue in key_issues)
            has_revoked = any('revoked' in issue for issue in key_issues)
            
            if has_revoked:
                status = 'warning'
                message = f'Found {len(found_selectors)} DKIM selector(s) but some keys are revoked'
            elif has_weak_key:
                status = 'warning'
                message = f'Found {len(found_selectors)} DKIM selector(s) with weak key(s) (1024-bit)'
            elif third_party_only:
                status = 'partial'
                if key_strengths:
                    message = f'Found DKIM for {len(found_selectors)} selector(s) ({", ".join(set(key_strengths))}) but none for primary mail platform ({primary_provider})'
                else:
                    message = f'Found DKIM for {len(found_selectors)} selector(s) but none for primary mail platform ({primary_provider})'
            else:
                status = 'success'
                if key_strengths:
                    message = f'Found DKIM for {len(found_selectors)} selector(s) with strong keys ({", ".join(set(key_strengths))})'
                else:
                    message = f'Found DKIM records for {len(found_selectors)} selector(s)'
        else:
            status = 'info'
            message = 'DKIM not discoverable via common selectors (large providers use rotating selectors)'
        
        return {
            'status': status,
            'message': message,
            'selectors': found_selectors,
            'key_issues': key_issues,
            'key_strengths': list(set(key_strengths)),
            'primary_provider': primary_provider,
            'security_gateway': security_gateway,
            'primary_has_dkim': primary_has_dkim,
            'third_party_only': third_party_only,
            'primary_dkim_note': primary_dkim_note,
            'found_providers': list(sorted(found_providers))
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
            'policy_error': None,
            'hosting_cname': None
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
        
        hosting_cname = None
        try:
            mta_sts_host = f"mta-sts.{domain}"
            cname_records = self.dns_query("CNAME", mta_sts_host)
            if cname_records:
                hosting_cname = cname_records[0].rstrip('.')
        except Exception:
            pass

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
            'policy_error': policy_data.get('error'),
            'hosting_cname': hosting_cname
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
            response = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': self.USER_AGENT})
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
            'has_iodef': has_iodef,
            'mpic_note': 'Since September 2025, all public CAs must verify domain control from multiple geographic locations (Multi-Perspective Issuance Corroboration, CA/B Forum Ballot SC-067). CAA records are now checked from multiple network perspectives before certificate issuance.'
        }
    
    DANE_MX_CAPABILITY = DANE_MX_CAPABILITY

    def _detect_mx_dane_capability(self, mx_hosts: List[str]) -> Optional[Dict[str, Any]]:
        """Detect if MX hosts belong to a known provider and return DANE capability info."""
        mx_str = ' '.join(h.lower() for h in mx_hosts)
        for provider_key, info in self.DANE_MX_CAPABILITY.items():
            for pattern in info['patterns']:
                if pattern in mx_str:
                    result = {
                        'provider_key': provider_key,
                        'provider_name': info['name'],
                        'dane_inbound': info['dane_inbound'],
                        'dane_outbound': info.get('dane_outbound', False),
                        'reason': info['reason'],
                        'alternative': info.get('alternative'),
                    }
                    if info.get('dane_migration_available'):
                        result['dane_migration_available'] = True
                    return result
        return None

    def analyze_dane(self, domain: str, mx_records: List[str] = None) -> Dict[str, Any]:
        """Check DANE/TLSA records for domain's mail servers (RFC 6698, RFC 7672).

        DANE (DNS-based Authentication of Named Entities) publishes TLS
        certificate information in DNSSEC-signed TLSA DNS records, enabling
        mail servers to verify TLS certificates without relying solely on
        certificate authorities.

        For SMTP, TLSA records are queried at _25._tcp.<mx_host>.

        Certificate Usage values (RFC 6698 §2.1.1):
          0 = PKIX-TA  (CA constraint, PKIX-validated)
          1 = PKIX-EE  (Service certificate constraint, PKIX-validated)
          2 = DANE-TA  (Trust anchor assertion, no PKIX required)
          3 = DANE-EE  (Domain-issued certificate, no PKIX required)

        Selector values (RFC 6698 §2.1.2):
          0 = Full certificate
          1 = SubjectPublicKeyInfo (public key only)

        Matching Type values (RFC 6698 §2.1.3):
          0 = Exact match (full DER)
          1 = SHA-256 hash
          2 = SHA-512 hash
        """
        import dns.resolver

        base_result = {
            'status': 'info',
            'message': 'No DANE/TLSA records found for mail servers',
            'has_dane': False,
            'mx_hosts_checked': 0,
            'mx_hosts_with_dane': 0,
            'tlsa_records': [],
            'requires_dnssec': True,
            'issues': [],
            'mx_provider': None,
            'dane_deployable': True,
        }

        if not mx_records:
            base_result['message'] = 'No MX records available — DANE check skipped'
            base_result['status'] = 'info'
            return base_result

        mx_hosts = []
        for mx in mx_records:
            parts = mx.strip().split()
            if len(parts) >= 2:
                host = parts[-1].rstrip('.')
                if host and host != '.':
                    mx_hosts.append(host)
            elif len(parts) == 1:
                host = parts[0].rstrip('.')
                if host and host != '.':
                    mx_hosts.append(host)

        if not mx_hosts:
            base_result['message'] = 'No valid MX hosts — DANE check skipped'
            return base_result

        mx_hosts = list(dict.fromkeys(mx_hosts))[:10]

        mx_capability = self._detect_mx_dane_capability(mx_hosts)
        if mx_capability:
            base_result['mx_provider'] = mx_capability
            base_result['dane_deployable'] = mx_capability['dane_inbound']
            if not mx_capability['dane_inbound']:
                logging.info(f"[DANE] MX provider {mx_capability['provider_name']} does not support inbound DANE for {domain}")

        usage_names = {
            0: 'PKIX-TA (CA constraint)',
            1: 'PKIX-EE (Certificate constraint)',
            2: 'DANE-TA (Trust anchor)',
            3: 'DANE-EE (Domain-issued certificate)'
        }
        selector_names = {
            0: 'Full certificate',
            1: 'Public key only (SubjectPublicKeyInfo)'
        }
        matching_names = {
            0: 'Exact match',
            1: 'SHA-256',
            2: 'SHA-512'
        }

        all_tlsa = []
        hosts_with_dane = []
        issues = []

        def check_mx_tlsa(mx_host):
            tlsa_name = f"_25._tcp.{mx_host}"
            found = []
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['1.1.1.1', '8.8.8.8']
                resolver.timeout = 3
                resolver.lifetime = 5
                answers = resolver.resolve(tlsa_name, 'TLSA')
                for rdata in answers:
                    usage = rdata.usage
                    selector = rdata.selector
                    mtype = rdata.mtype
                    cert_data = rdata.cert.hex()

                    rec = {
                        'mx_host': mx_host,
                        'tlsa_name': tlsa_name,
                        'usage': usage,
                        'usage_name': usage_names.get(usage, f'Unknown ({usage})'),
                        'selector': selector,
                        'selector_name': selector_names.get(selector, f'Unknown ({selector})'),
                        'matching_type': mtype,
                        'matching_name': matching_names.get(mtype, f'Unknown ({mtype})'),
                        'certificate_data': cert_data[:64] + '...' if len(cert_data) > 64 else cert_data,
                        'full_record': f'{usage} {selector} {mtype} {cert_data[:64]}...'
                    }

                    if usage in (0, 1):
                        rec['recommendation'] = 'RFC 7672 §3.1 recommends usage 2 (DANE-TA) or 3 (DANE-EE) for SMTP'

                    found.append(rec)
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoNameservers:
                pass
            except Exception:
                pass
            return mx_host, found

        timed_out_hosts = []
        with ThreadPoolExecutor(max_workers=min(len(mx_hosts), 5)) as executor:
            futures = {executor.submit(check_mx_tlsa, host): host for host in mx_hosts}
            try:
                for future in as_completed(futures, timeout=10):
                    try:
                        mx_host, records = future.result(timeout=5)
                        if records:
                            hosts_with_dane.append(mx_host)
                            all_tlsa.extend(records)
                    except Exception:
                        pass
            except FuturesTimeoutError:
                logging.warning(f"DANE/TLSA lookup timed out for {domain}, returning partial results")
                for future, host in futures.items():
                    if not future.done():
                        timed_out_hosts.append(host)

        base_result['mx_hosts_checked'] = len(mx_hosts)
        base_result['mx_hosts_with_dane'] = len(hosts_with_dane)
        base_result['tlsa_records'] = all_tlsa

        if timed_out_hosts:
            issues.append(f"TLSA lookup timed out for: {', '.join(timed_out_hosts[:3])}")

        if all_tlsa:
            base_result['has_dane'] = True
            base_result['status'] = 'success'

            for rec in all_tlsa:
                if rec['usage'] in (0, 1):
                    issues.append(f"TLSA for {rec['mx_host']}: usage {rec['usage']} (PKIX-based) — RFC 7672 §3.1 recommends usage 2 or 3 for SMTP")
                if rec['matching_type'] == 0:
                    issues.append(f"TLSA for {rec['mx_host']}: exact match (type 0) — SHA-256 (type 1) is preferred for resilience")

            if len(hosts_with_dane) == len(mx_hosts):
                base_result['message'] = f'DANE configured — TLSA records found for all {len(mx_hosts)} MX host{"s" if len(mx_hosts) > 1 else ""}'
            else:
                base_result['message'] = f'DANE partially configured — TLSA records on {len(hosts_with_dane)}/{len(mx_hosts)} MX hosts'
                base_result['status'] = 'warning'
                missing = [h for h in mx_hosts if h not in hosts_with_dane]
                issues.append(f"Missing DANE for: {', '.join(missing[:3])}")
        elif timed_out_hosts:
            base_result['status'] = 'timeout'
            base_result['message'] = f'DANE/TLSA lookup timed out (checked {len(mx_hosts)} MX host{"s" if len(mx_hosts) > 1 else ""})'
        else:
            base_result['status'] = 'info'
            if mx_capability and not mx_capability['dane_inbound']:
                provider_name = mx_capability['provider_name']
                alt = mx_capability.get('alternative', 'MTA-STS')
                if mx_capability.get('dane_migration_available'):
                    base_result['message'] = f'DANE not available on current MX endpoints — {provider_name} supports DANE on newer endpoints (migration available)'
                else:
                    base_result['message'] = f'DANE not available — {provider_name} does not support inbound DANE/TLSA on its MX infrastructure'
                base_result['dane_deployable'] = False
            else:
                base_result['message'] = f'No DANE/TLSA records found (checked {len(mx_hosts)} MX host{"s" if len(mx_hosts) > 1 else ""})'

        base_result['issues'] = issues
        return base_result

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
            response = requests.head(url, timeout=5, allow_redirects=True, headers={'User-Agent': self.USER_AGENT})
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
                    get_resp = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': self.USER_AGENT})
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
            response = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': self.USER_AGENT})
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
        """Check DNSSEC status for domain by looking for DNSKEY, DS records, and AD flag."""
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
        
        # Check AD (Authentic Data) flag - indicates resolver validated DNSSEC
        ad_result = self.check_dnssec_ad_flag(domain)
        ad_flag = ad_result.get('ad_flag', False)
        ad_resolver = ad_result.get('resolver_used')
        
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
            # Enhance message based on AD flag
            if ad_flag:
                message = 'DNSSEC fully configured and validated - AD flag confirmed by resolver'
            else:
                message = 'DNSSEC configured (DNSKEY + DS present) but AD flag not set by resolver'
            return {
                'status': 'success',
                'message': message,
                'has_dnskey': True,
                'has_ds': True,
                'dnskey_records': dnskey_records,
                'ds_records': ds_records,
                'algorithm': algorithm,
                'algorithm_name': algorithm_name,
                'chain_of_trust': 'complete',
                'ad_flag': ad_flag,
                'ad_resolver': ad_resolver
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
                'chain_of_trust': 'broken',
                'ad_flag': False,
                'ad_resolver': ad_resolver
            }
        else:
            if ad_flag:
                parent_zone = self._find_parent_zone(domain)
                parent_algo = None
                parent_algo_name = None
                if parent_zone:
                    try:
                        parent_ds = self.dns_query("DS", parent_zone)
                        if parent_ds:
                            ds_parts = parent_ds[0].split()
                            if len(ds_parts) >= 2:
                                alg_num = int(ds_parts[1])
                                parent_algo = alg_num
                                parent_algo_name = algorithm_names.get(alg_num, f'Algorithm {alg_num}')
                    except Exception:
                        pass
                return {
                    'status': 'success',
                    'message': f'DNSSEC inherited from parent zone ({parent_zone}) - DNS responses are authenticated' if parent_zone else 'DNSSEC validated by resolver - DNS responses are authenticated',
                    'has_dnskey': False,
                    'has_ds': False,
                    'dnskey_records': [],
                    'ds_records': [],
                    'algorithm': parent_algo,
                    'algorithm_name': parent_algo_name,
                    'chain_of_trust': 'inherited',
                    'ad_flag': True,
                    'ad_resolver': ad_resolver,
                    'is_subdomain': True,
                    'parent_zone': parent_zone
                }
            return {
                'status': 'warning',
                'message': 'DNSSEC not configured - DNS responses are unsigned',
                'has_dnskey': False,
                'has_ds': False,
                'dnskey_records': [],
                'ds_records': [],
                'algorithm': None,
                'algorithm_name': None,
                'chain_of_trust': 'none',
                'ad_flag': False,
                'ad_resolver': None
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
            parent_zone = self._find_parent_zone(domain)
            if parent_zone:
                parent_zone_ns = []
                try:
                    pz_result = self.dns_query("NS", parent_zone)
                    if pz_result:
                        parent_zone_ns = sorted([ns.rstrip('.').lower() for ns in pz_result if ns])
                except Exception:
                    pass
                return {
                    'status': 'success',
                    'message': f'Subdomain within {parent_zone} zone - no separate delegation needed',
                    'child_ns': [],
                    'parent_ns': parent_zone_ns,
                    'match': None,
                    'delegation_ok': True,
                    'is_subdomain': True,
                    'parent_zone': parent_zone
                }
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
        
        # Check if we have cached RDAP data
        cached_at = None
        from_cache = False
        cached_data = _rdap_cache.get(domain)
        if cached_data is not None:
            from_cache = True
            cached_at = cached_data.get('_cached_at', 'recently')
        
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
                    result: Dict[str, Any] = {'status': 'success', 'source': 'RDAP', 'registrar': reg_str}
                    if from_cache and cached_at:
                        result['cached'] = True
                        result['cached_at'] = cached_at
                    return result
                else:
                    logging.warning(f"[REGISTRAR] RDAP data found but no valid registrar name")
            else:
                logging.warning(f"[REGISTRAR] RDAP returned no data")
        except Exception as e:
            logging.warning(f"[REGISTRAR] RDAP failed: {e}")
        
        # RDAP failed - fall back to WHOIS (backup source)
        logging.info(f"[REGISTRAR] RDAP failed, trying WHOIS as backup...")
        whois_restricted = False
        whois_restricted_tld = None
        try:
            whois_result = self._whois_lookup_registrar(domain)
            if whois_result:
                if whois_result.startswith('__RESTRICTED__'):
                    whois_restricted = True
                    whois_restricted_tld = whois_result.replace('__RESTRICTED__', '')
                    logging.info(f"[REGISTRAR] WHOIS access restricted for .{whois_restricted_tld}")
                else:
                    logging.info(f"[REGISTRAR] SUCCESS via WHOIS (backup): {whois_result}")
                    return {'status': 'success', 'source': 'WHOIS', 'registrar': whois_result}
        except Exception as e:
            logging.warning(f"[REGISTRAR] WHOIS failed: {e}")
        
        parent_zone = self._find_parent_zone(domain)
        
        # For subdomains, try parent zone RDAP/WHOIS before NS inference
        if parent_zone and parent_zone != domain:
            logging.info(f"[REGISTRAR] Trying parent zone {parent_zone} for subdomain {domain}")
            parent_result = self.get_registrar_info(parent_zone)
            if parent_result.get('status') == 'success':
                parent_result['subdomain_of'] = parent_zone
                return parent_result
        
        # Try NS-based inference as third fallback
        lookup_domain = parent_zone if (parent_zone and parent_zone != domain) else domain
        
        ns_result = self._infer_registrar_from_ns(lookup_domain)
        if ns_result:
            if lookup_domain != domain:
                ns_result['subdomain_of'] = lookup_domain
            if whois_restricted:
                ns_result['registry_restricted'] = True
                ns_result['registry_restricted_tld'] = whois_restricted_tld
            return ns_result

        logging.warning(f"[REGISTRAR] FAILED - No registrar info found for {domain}")
        
        if whois_restricted:
            restricted_registries = {
                'es': 'Red.es (Spain)',
                'br': 'Registro.br (Brazil)',
                'kr': 'KISA (South Korea)',
                'cn': 'CNNIC (China)',
                'ru': 'RIPN (Russia)',
            }
            registry_name = restricted_registries.get(whois_restricted_tld, f'.{whois_restricted_tld} registry')
            return {
                'status': 'restricted',
                'source': 'WHOIS',
                'registrar': None,
                'registry_restricted': True,
                'registry_restricted_tld': whois_restricted_tld,
                'message': f'{registry_name} restricts public WHOIS/RDAP access — registrar data requires authorized IP',
            }
        
        return {
            'status': 'error',
            'source': None,
            'registrar': None,
            'message': 'Registry data unavailable (RDAP/WHOIS services unreachable or rate-limited)'
        }
    
    def _rdap_lookup(self, domain: str) -> Dict:
        """Return RDAP JSON data for domain using whodap library with retry."""
        import whodap
        
        # Check cache first to avoid hammering registries
        cached_data = _rdap_cache.get(domain)
        if cached_data is not None:
            logging.warning(f"[RDAP] Using cached data for {domain}")
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
                # Cache the result with timestamp
                data['_cached_at'] = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
                _rdap_cache.set(domain, data)
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
            'User-Agent': self.USER_AGENT
        }
        
        direct_endpoints = {
            'com': 'https://rdap.verisign.com/com/v1/',
            'net': 'https://rdap.verisign.com/net/v1/',
            'org': 'https://rdap.publicinterestregistry.net/rdap/',
            'info': 'https://rdap.afilias.net/rdap/info/',
            'biz': 'https://rdap.afilias.net/rdap/biz/',
            'mobi': 'https://rdap.afilias.net/rdap/mobi/',
            'io': 'https://rdap.nic.io/',
            'tech': 'https://rdap.centralnic.com/tech/',
            'dev': 'https://rdap.nic.google/',
            'app': 'https://rdap.nic.google/',
            'us': 'https://rdap.nic.us/',
            'uk': 'https://rdap.nominet.uk/uk/',
            'ca': 'https://rdap.ca.fury.ca/rdap/',
            'au': 'https://rdap.auda.org.au/rdap/',
            'nz': 'https://rdap.dnc.org.nz/',
            'ie': 'https://rdap.weare.ie/',
            'za': 'https://rdap.registry.net.za/rdap/',
            'nl': 'https://rdap.sidn.nl/rdap/',
            'eu': 'https://rdap.eu/',
            'gov': 'https://rdap.cloudflare.com/rdap/',
            'edu': 'https://rdap.arin.net/registry/',
            'co': 'https://rdap.nic.co/',
            'me': 'https://rdap.nic.me/',
            'ai': 'https://rdap.nic.ai/',
            'gg': 'https://rdap.channelisles.net/rdap/',
            'je': 'https://rdap.channelisles.net/rdap/',
            'im': 'https://rdap.nic.im/',
            'sg': 'https://rdap.sgnic.sg/',
            'hk': 'https://rdap.hkirc.hk/',
            'cc': 'https://rdap.verisign.com/cc/v1/',
            'tv': 'https://rdap.verisign.com/tv/v1/',
            'xyz': 'https://rdap.centralnic.com/xyz/',
            'online': 'https://rdap.centralnic.com/online/',
            'site': 'https://rdap.centralnic.com/site/',
            'store': 'https://rdap.centralnic.com/store/',
            'cloud': 'https://rdap.centralnic.com/cloud/',
            'cz': 'https://rdap.nic.cz/',
            'fi': 'https://rdap.fi/rdap/rdap/',
            'no': 'https://rdap.norid.no/',
            'si': 'https://rdap.register.si/',
            'is': 'https://rdap.isnic.is/rdap/',
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
                    # Cache the result with timestamp
                    data['_cached_at'] = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
                    _rdap_cache.set(domain, data)
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
            'biz': 'whois.biz',
            'mobi': 'whois.afilias.net',
            'name': 'whois.nic.name',
            'io': 'whois.nic.io',
            'tech': 'whois.nic.tech',
            'dev': 'whois.nic.google',
            'app': 'whois.nic.google',
            'co': 'whois.nic.co',
            'me': 'whois.nic.me',
            'uk': 'whois.nic.uk',
            'us': 'whois.nic.us',
            'ca': 'whois.cira.ca',
            'au': 'whois.auda.org.au',
            'nz': 'whois.srs.net.nz',
            'ie': 'whois.weare.ie',
            'za': 'whois.registry.net.za',
            'sg': 'whois.sgnic.sg',
            'hk': 'whois.hkirc.hk',
            'ph': 'whois.dot.ph',
            'in': 'whois.registry.in',
            'ai': 'whois.nic.ai',
            'gg': 'whois.gg',
            'je': 'whois.je',
            'im': 'whois.nic.im',
            'cc': 'whois.verisign-grs.com',
            'tv': 'whois.verisign-grs.com',
            'ws': 'whois.website.ws',
            'to': 'whois.tonic.to',
            'ly': 'whois.nic.ly',
            'fm': 'whois.nic.fm',
            'gov': 'whois.dotgov.gov',
            'edu': 'whois.educause.edu',
            'eu': 'whois.eu',
            'de': 'whois.denic.de',
            'fr': 'whois.nic.fr',
            'it': 'whois.nic.it',
            'nl': 'whois.sidn.nl',
            'be': 'whois.dns.be',
            'at': 'whois.nic.at',
            'ch': 'whois.nic.ch',
            'se': 'whois.iis.se',
            'pl': 'whois.dns.pl',
            'br': 'whois.registro.br',
            'jp': 'whois.jprs.jp',
            'ru': 'whois.tcinet.ru',
            'xyz': 'whois.nic.xyz',
            'online': 'whois.centralnic.com',
            'site': 'whois.centralnic.com',
            'store': 'whois.centralnic.com',
            'cloud': 'whois.centralnic.com',
            'lu': 'whois.dns.lu',
            'dk': 'whois.dk-hostmaster.dk',
            'fi': 'whois.fi',
            'no': 'whois.norid.no',
            'es': 'whois.nic.es',
            'pt': 'whois.dns.pt',
            'cz': 'whois.nic.cz',
            'sk': 'whois.sk-nic.sk',
            'hr': 'whois.dns.hr',
            'ro': 'whois.rotld.ro',
            'hu': 'whois.nic.hu',
            'bg': 'whois.register.bg',
            'lt': 'whois.domreg.lt',
            'lv': 'whois.nic.lv',
            'ee': 'whois.tld.ee',
            'gr': 'whois.nic.gr',
            'si': 'whois.register.si',
            'is': 'whois.isnic.is',
            'rs': 'whois.rnids.rs',
            'li': 'whois.nic.li',
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
            
            output_lower = output.lower()
            restricted_indicators = [
                'not authorised', 'not authorized', 'no autorizada',
                'access denied', 'authorization required',
                'ip address used to perform the query',
                'exceeded the established limit', 'exceeded the maximum',
                'request access to the service',
                'access to whois is restricted', 'access restricted',
                'you are not allowed', 'permission denied',
                'query rate limit exceeded', 'too many queries',
                'connection refused', 'service unavailable',
            ]
            if any(indicator in output_lower for indicator in restricted_indicators):
                logging.warning(f"[WHOIS] Registry restricts WHOIS access for .{tld} domains")
                return f"__RESTRICTED__{tld}"
            
            stripped = output.strip()
            if len(stripped) < 50 and not re.search(r'(?i)(registr|domain|creat|expir)', stripped):
                logging.warning(f"[WHOIS] Unusable response ({len(stripped)} bytes) for .{tld}")
                return f"__RESTRICTED__{tld}"
            
            registrar = None
            registrant = None
            
            registrar_match = re.search(r"(?i)^(?:registrar|sponsoring registrar|registrar[- ]name)\s*:\s*(.+)$", output, re.MULTILINE)
            if registrar_match:
                val = registrar_match.group(1).strip()
                if val and not val.lower().startswith('http') and val.lower() != 'not available':
                    registrar = val
            
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
    
    def _infer_registrar_from_ns(self, domain: str) -> Optional[Dict[str, Any]]:
        """Infer registrar/hosting provider from NS records when RDAP/WHOIS are unavailable.
        
        Many registrars use distinctive nameserver patterns. While NS records
        technically indicate DNS hosting (not necessarily the registrar), for
        registrar-integrated DNS like Gandi, OVH, and others, the NS records
        reliably indicate the registrar.
        """
        try:
            r = dns.resolver.Resolver()
            r.nameservers = ['1.1.1.1', '8.8.8.8']
            r.lifetime = 4.0
            r.timeout = 3.0
            
            answers = r.resolve(domain, 'NS')
            ns_list = [str(rdata.target).rstrip('.').lower() for rdata in answers]
        except Exception:
            return None
        
        ns_str = ' '.join(ns_list)
        
        ns_registrar_patterns = {
            'gandi.net': 'Gandi SAS',
            'ovh.net': 'OVHcloud',
            'ovh.com': 'OVHcloud',
            'domaincontrol.com': 'GoDaddy',
            'registrar-servers.com': 'Namecheap',
            'name-services.com': 'Enom / Tucows',
            'hostgator.com': 'HostGator',
            'bluehost.com': 'Bluehost',
            'dreamhost.com': 'DreamHost',
            'ionos.com': '1&1 IONOS',
            'ui-dns.com': '1&1 IONOS',
            'ui-dns.de': '1&1 IONOS',
            'ui-dns.org': '1&1 IONOS',
            'ui-dns.biz': '1&1 IONOS',
            'strato.de': 'Strato',
            'strato-hosting.eu': 'Strato',
            'hetzner.com': 'Hetzner',
            'netcup.net': 'Netcup',
            'inwx.de': 'INWX',
            'inwx.eu': 'INWX',
            'hover.com': 'Hover / Tucows',
            'porkbun.com': 'Porkbun',
            'dynadot.com': 'Dynadot',
            'epik.com': 'Epik',
            'sav.com': 'SAV',
            'squarespace.com': 'Squarespace Domains',
            'wixdns.net': 'Wix',
            'wordpress.com': 'WordPress.com',
            'pair.com': 'pair Domains',
            'aruba.it': 'Aruba S.p.A.',
            'dnsmadeeasy.com': 'DNS Made Easy',
            'netim.net': 'Netim',
            'infomaniak.ch': 'Infomaniak',
            'bookmyname.com': 'BookMyName (Gandi)',
            'one.com': 'one.com',
            'hostpoint.ch': 'Hostpoint',
        }
        
        for pattern, registrar_name in ns_registrar_patterns.items():
            if pattern in ns_str:
                logging.info(f"[REGISTRAR] Inferred '{registrar_name}' from NS records ({pattern}) for {domain}")
                return {
                    'status': 'success',
                    'source': 'NS inference',
                    'registrar': registrar_name,
                    'ns_inferred': True,
                    'caveat': 'Inferred from nameserver records — indicates DNS hosting provider, which for integrated registrars typically matches the registrar.',
                }
        
        return None
    
    def analyze_dns_infrastructure(self, domain: str, results: Dict) -> Dict[str, Any]:
        """Analyze DNS infrastructure to detect enterprise providers and security posture.
        
        Detects:
        - Enterprise DNS providers (Cloudflare, AWS, Google, Akamai, Azure, etc.)
        - Self-hosted enterprise DNS (Apple, Microsoft, Meta, etc.)
        - Government domains (.gov, .mil, .gov.uk, .gov.au, .gc.ca)
        - Managed DNS providers (DigitalOcean, Namecheap, GoDaddy, etc.)
        
        Args:
            domain: The domain being analyzed
            results: Dict containing basic_records, caa_analysis, dnssec_analysis
            
        Returns:
            Dict with provider_tier ('enterprise'/'managed'/'standard'),
            is_government flag, alt_security_items, and assessment label.
        """
        ns_records = results.get('basic_records', {}).get('NS', [])
        ns_str = " ".join(r for r in ns_records if r).lower()
        
        # Enterprise-grade DNS providers with security features
        # These provide: DDoS protection, rate limiting, DNSSEC signing (optional), monitoring
        enterprise_providers = {
            'cloudflare': {'name': 'Cloudflare', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Auto-DNSSEC available']},
            'awsdns': {'name': 'Amazon Route 53', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Health checks']},
            'route53': {'name': 'Amazon Route 53', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Health checks']},
            'ultradns': {'name': 'Vercara UltraDNS', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'DNSSEC support']},
            'akam': {'name': 'Akamai Edge DNS', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Global distribution']},
            'dynect': {'name': 'Oracle Dyn', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Traffic management']},
            'oraclecloud': {'name': 'Oracle Cloud DNS', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Cloud integration']},
            'nsone': {'name': 'NS1 (IBM)', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Intelligent DNS']},
            'azure-dns': {'name': 'Azure DNS', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Azure integration']},
            'google': {'name': 'Google Cloud DNS', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Auto-scaling']},
            'verisign': {'name': 'Verisign DNS', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Critical infrastructure']},
            'f5cloudservices': {'name': 'F5 Distributed Cloud DNS', 'tier': 'enterprise', 'features': ['DDoS protection', 'Anycast', 'Global distribution']},
            'uu.net': {'name': 'Verizon Business DNS', 'tier': 'enterprise', 'features': ['Enterprise infrastructure', 'Global backbone', 'Managed security']},
            'els-gms.att.net': {'name': 'AT&T Managed DNS', 'tier': 'enterprise', 'features': ['Enterprise infrastructure', 'Global backbone', 'Managed security']},
            'csc.com': {'name': 'CSC Global DNS', 'tier': 'enterprise', 'features': ['Enterprise management', 'Brand protection', 'Global infrastructure']},
            'cscdns': {'name': 'CSC Global DNS', 'tier': 'enterprise', 'features': ['Enterprise management', 'Brand protection', 'Global infrastructure']},
            'markmonitor': {'name': 'MarkMonitor DNS', 'tier': 'enterprise', 'features': ['Brand protection', 'Enterprise management', 'Anti-fraud']},
            'comlaude-dns': {'name': 'Com Laude DNS', 'tier': 'enterprise', 'features': ['Brand protection', 'Enterprise management', 'Global infrastructure']},
            'bt.net': {'name': 'BT (British Telecom)', 'tier': 'enterprise', 'features': ['Enterprise infrastructure', 'Managed security', 'UK backbone']},
        }
        
        # Major companies running their own enterprise-grade DNS infrastructure
        # These are self-hosted but have the same security posture as enterprise providers
        self_hosted_enterprise = {
            'ns.apple.com': {'name': 'Apple (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'microsoft.com': {'name': 'Microsoft (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'facebook.com': {'name': 'Meta (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'meta.com': {'name': 'Meta (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'amazon.com': {'name': 'Amazon (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'netflix.com': {'name': 'Netflix (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'twitter.com': {'name': 'X/Twitter (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'x.com': {'name': 'X/Twitter (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'ibm.com': {'name': 'IBM (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'oracle.com': {'name': 'Oracle (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'cisco.com': {'name': 'Cisco (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'intel.com': {'name': 'Intel (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'salesforce.com': {'name': 'Salesforce (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
            'adobe.com': {'name': 'Adobe (Self-Hosted)', 'tier': 'enterprise', 'features': ['Self-managed infrastructure', 'Global Anycast', 'Enterprise security']},
        }
        
        # Government entities - always enterprise-grade security
        # Many use Akamai, UltraDNS, or self-hosted secure infrastructure
        government_domains = {
            '.gov': {'name': 'U.S. Government', 'tier': 'enterprise', 'features': ['Government security standards', 'FISMA compliance', 'Protected infrastructure']},
            '.mil': {'name': 'U.S. Military', 'tier': 'enterprise', 'features': ['Military security standards', 'DoD compliance', 'Protected infrastructure']},
            '.gov.uk': {'name': 'UK Government', 'tier': 'enterprise', 'features': ['Government security standards', 'NCSC compliance', 'Protected infrastructure']},
            '.gov.au': {'name': 'Australian Government', 'tier': 'enterprise', 'features': ['Government security standards', 'ASD compliance', 'Protected infrastructure']},
            '.gc.ca': {'name': 'Canadian Government', 'tier': 'enterprise', 'features': ['Government security standards', 'GC compliance', 'Protected infrastructure']},
        }
        
        # Managed DNS providers - good security but not enterprise-grade
        managed_providers = {
            'digitalocean': {'name': 'DigitalOcean', 'tier': 'managed'},
            'linode': {'name': 'Linode', 'tier': 'managed'},
            'vultr': {'name': 'Vultr', 'tier': 'managed'},
            'porkbun': {'name': 'Porkbun', 'tier': 'managed'},
            'namecheap': {'name': 'Namecheap', 'tier': 'managed'},
            'registrar-servers': {'name': 'Namecheap', 'tier': 'managed'},
            'namesilo': {'name': 'NameSilo', 'tier': 'managed'},
            'godaddy': {'name': 'GoDaddy', 'tier': 'managed'},
            'domaincontrol': {'name': 'GoDaddy', 'tier': 'managed'},
        }
        
        provider_info = None
        provider_tier = 'standard'
        provider_features = []
        
        # Check enterprise providers - pick the one with most nameservers when multiple match
        ns_list = [r.lower() for r in ns_records if r]
        matched_enterprise = {}
        for key, info in enterprise_providers.items():
            count = sum(1 for ns in ns_list if key in ns)
            if count > 0:
                matched_enterprise[key] = (info, count)
        
        secondary_providers = []
        if matched_enterprise:
            best_key = max(matched_enterprise, key=lambda k: matched_enterprise[k][1])
            provider_info = matched_enterprise[best_key][0]
            provider_tier = 'enterprise'
            provider_features = provider_info.get('features', [])
            for key, (info, count) in matched_enterprise.items():
                if key != best_key:
                    secondary_providers.append(info['name'])
        
        # Check self-hosted enterprise DNS (major tech companies)
        if not provider_info:
            for key, info in self_hosted_enterprise.items():
                if key in ns_str:
                    provider_info = info
                    provider_tier = 'enterprise'
                    provider_features = info.get('features', [])
                    break
        
        # Check managed providers if no enterprise match
        if not provider_info:
            for key, info in managed_providers.items():
                if key in ns_str:
                    provider_info = info
                    provider_tier = 'managed'
                    break
        
        # Check if domain itself is a government entity (always enterprise-grade)
        domain_lower = domain.lower()
        is_government = False
        for gov_suffix, gov_info in government_domains.items():
            if domain_lower.endswith(gov_suffix):
                is_government = True
                # Government domains get enterprise tier regardless of DNS provider
                if provider_tier != 'enterprise':
                    provider_tier = 'enterprise'
                    provider_features = gov_info.get('features', [])
                # Update provider info to reflect government status
                if provider_info:
                    provider_info = {'name': f"{gov_info['name']} via {provider_info['name']}", 'tier': 'enterprise'}
                else:
                    provider_info = gov_info
                break
        
        # Get CAA status from results
        caa_analysis = results.get('caa_analysis', {})
        has_caa = caa_analysis.get('status') == 'success' or bool(caa_analysis.get('records', []))
        
        # Get DNSSEC status from results
        dnssec_analysis = results.get('dnssec_analysis', {})
        has_dnssec = dnssec_analysis.get('status') == 'success'
        
        # Determine alternative security status
        # Enterprise provider + CAA = strong alternative security stack
        # Enterprise provider alone = moderate alternative security
        alt_security_score = 0
        alt_security_items = []
        
        if provider_tier == 'enterprise' and provider_info:
            alt_security_score += 2
            alt_security_items.append(f"{provider_info['name']} (enterprise DNS with DDoS protection)")
            for sp in secondary_providers:
                alt_security_items.append(f"{sp} (secondary/backup DNS)")
        elif provider_tier == 'managed' and provider_info:
            alt_security_score += 1
            alt_security_items.append(f"{provider_info['name']} (managed DNS)")
        
        if has_caa:
            alt_security_score += 1
            alt_security_items.append("CAA records (certificate issuance control)")
        
        # Determine overall infrastructure security assessment
        if has_dnssec and provider_tier == 'enterprise':
            assessment = 'maximum'
            assessment_label = 'Maximum Security'
            message = 'Enterprise DNS provider with DNSSEC - comprehensive DNS security'
        elif provider_tier == 'enterprise' and has_caa:
            assessment = 'enterprise'
            assessment_label = 'Enterprise Security'
            message = 'Enterprise-grade DNS infrastructure with certificate controls - industry-standard for large organizations'
        elif provider_tier == 'enterprise':
            assessment = 'enterprise'
            assessment_label = 'Enterprise Infrastructure'
            message = 'Enterprise-grade DNS provider with built-in DDoS protection and monitoring'
        elif has_dnssec:
            assessment = 'secured'
            assessment_label = 'DNSSEC Secured'
            message = 'DNS responses cryptographically signed'
        elif provider_tier == 'managed' and has_caa:
            assessment = 'managed'
            assessment_label = 'Managed Security'
            message = 'Managed DNS with certificate controls'
        elif provider_tier == 'managed':
            assessment = 'managed'
            assessment_label = 'Managed DNS'
            message = 'Using managed DNS provider'
        else:
            assessment = 'standard'
            assessment_label = 'Standard'
            message = 'Standard DNS configuration'
        
        return {
            'status': 'success' if assessment in ['maximum', 'enterprise', 'secured'] else 'info',
            'assessment': assessment,
            'assessment_label': assessment_label,
            'message': message,
            'provider': provider_info['name'] if provider_info else 'Standard/Custom',
            'provider_tier': provider_tier,
            'provider_features': provider_features,
            'has_caa': has_caa,
            'has_dnssec': has_dnssec,
            'alt_security_score': alt_security_score,
            'alt_security_items': alt_security_items,
            'explains_no_dnssec': provider_tier == 'enterprise' and not has_dnssec,
            'is_government': is_government
        }
    
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
            'akam': 'Akamai Edge DNS',
            'ultradns': 'Vercara UltraDNS',
            'dynect': 'Oracle Dyn',
            'oraclecloud': 'Oracle Cloud DNS',
            'nsone': 'NS1 (IBM)',
            'verisign': 'Verisign DNS',
            'f5cloudservices': 'F5 Distributed Cloud DNS',
            'uu.net': 'Verizon Business DNS',
            'els-gms.att.net': 'AT&T Managed DNS',
            'csc.com': 'CSC Global DNS',
            'cscdns': 'CSC Global DNS',
            'markmonitor': 'MarkMonitor DNS',
            'comlaude-dns': 'Com Laude DNS',
            'bt.net': 'BT (British Telecom)',
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
            'squarespace': 'Squarespace',
            'ns.apple.com': 'Apple (Self-Hosted)',
            'ns.facebook.com': 'Meta (Self-Hosted)',
            '.intel.com': 'Intel (Self-Hosted)',
            'salesforce-dns.com': 'Salesforce (Self-Hosted)',
            'salesforce.com': 'Salesforce (Self-Hosted)',
            '.cisco.com': 'Cisco (Self-Hosted)',
        }
        
        ns_list_hosting = [r.lower() for r in ns_records if r]
        matched_dns = {}
        for key, name in dns_providers.items():
            count = sum(1 for ns in ns_list_hosting if key in ns)
            if count > 0:
                matched_dns[key] = (name, count)
        if matched_dns:
            best_key = max(matched_dns, key=lambda k: matched_dns[k][1])
            dns_hosting = matched_dns[best_key][0]

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
            'gpphosted': 'Proofpoint',
            'iphmx': 'Proofpoint',
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
        
        # Check for Null MX (RFC 7505) - domain explicitly does not accept mail
        if email_hosting == "Unknown" and mx_records:
            is_null_mx = any(
                r.strip().rstrip('.').replace(' ', '') in ['0.', '0'] or r.strip() == '0 .'
                for r in mx_records
            )
            if is_null_mx:
                email_hosting = "No Mail (Null MX)"
            else:
                first_mx = mx_records[0].split()[-1] if mx_records else ""
                if first_mx:
                    parts = first_mx.rstrip('.').split('.')
                    if len(parts) >= 2:
                        email_hosting = '.'.join(parts[-2:]).title()
        
        return {
            'hosting': hosting,
            'dns_hosting': dns_hosting,
            'email_hosting': email_hosting
        }

    def analyze_domain(self, domain: str, custom_dkim_selectors: list = None) -> Dict[str, Any]:
        """Perform complete DNS analysis of domain with parallel lookups for speed.
        
        Args:
            domain: The domain name to analyze (e.g., 'example.com')
            custom_dkim_selectors: Optional list of user-provided DKIM selectors to check
                                   (e.g., ['myselector._domainkey'])
            
        Returns:
            Dict containing comprehensive DNS analysis:
            - domain_exists: Whether the domain has DNS records
            - basic_records: A, AAAA, MX, NS, TXT, CNAME, SRV records
            - spf_analysis: SPF record analysis with lookup counts and issues
            - dmarc_analysis: DMARC policy analysis with alignment checks
            - dkim_analysis: DKIM selector discovery and key analysis
            - mta_sts_analysis: MTA-STS policy status
            - tlsrpt_analysis: TLS-RPT configuration
            - bimi_analysis: BIMI record and VMC validation
            - caa_analysis: CAA records for certificate control
            - dnssec_analysis: DNSSEC validation status
            - dns_infrastructure: Enterprise provider detection, government status
            - registrar_info: RDAP registrar data
            - posture: Overall security assessment and scorecard
        """
        
        # Early check: Does domain exist / is it delegated?
        # Use dns_query which uses DoH for reliability
        domain_exists = True
        domain_status = 'active'
        domain_status_message = None
        
        # Quick check for any records - if we can find A, AAAA, MX, or TXT, domain exists
        quick_check_records = []
        for rtype in ['A', 'TXT', 'MX']:
            result = self.dns_query(rtype, domain)
            if result:
                quick_check_records.extend(result)
                break  # Found records, domain exists
        
        if not quick_check_records:
            # No basic records found - domain likely doesn't exist or is undelegated
            # Try NS as final check
            ns_records = self.dns_query('NS', domain)
            if not ns_records:
                domain_exists = False
                domain_status = 'undelegated'
                domain_status_message = 'Domain is not delegated or has no DNS records. This may be an unused subdomain or unregistered domain.'
        
        # If domain clearly doesn't exist or is undelegated with no records, return early
        if not domain_exists:
            return {
                'domain_exists': False,
                'domain_status': domain_status,
                'domain_status_message': domain_status_message,
                'section_status': {},
                'basic_records': {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [], 'CNAME': [], 'SOA': []},
                'authoritative_records': {},
                'propagation_status': {},
                'spf_analysis': {'status': 'n/a', 'message': 'Domain does not exist'},
                'dmarc_analysis': {'status': 'n/a', 'message': 'Domain does not exist'},
                'dkim_analysis': {'status': 'n/a'},
                'mta_sts_analysis': {'status': 'n/a'},
                'tlsrpt_analysis': {'status': 'n/a'},
                'bimi_analysis': {'status': 'n/a'},
                'dane_analysis': {'status': 'n/a', 'has_dane': False, 'tlsa_records': [], 'issues': []},
                'caa_analysis': {'status': 'n/a'},
                'dnssec_analysis': {'status': 'n/a'},
                'ns_delegation_analysis': {'status': 'error', 'delegation_ok': False, 'message': 'Domain does not exist'},
                'registrar_info': {'status': 'n/a', 'registrar': None},
                'smtp_transport': None,
                'ct_subdomains': {'status': 'success', 'subdomains': [], 'unique_subdomains': 0, 'total_certs': 0, 'source': 'Certificate Transparency Logs', 'caveat': 'Domain does not exist or is not delegated.', 'is_analyzed_subdomain': False, 'registered_domain': None},
                'email_security_mgmt': {'actively_managed': False, 'providers': [], 'spf_flattening': None, 'provider_count': 0},
                'hosting_summary': {'hosting': 'N/A', 'dns_hosting': 'N/A', 'email_hosting': 'N/A'},
                'posture': {
                    'score': 0,
                    'grade': 'N/A',
                    'label': 'Non-existent Domain',
                    'issues': ['Domain does not exist or is not delegated'],
                    'color': 'secondary'
                }
            }
        
        analysis_start = time.time()
        futures = {
            self._executor.submit(self.get_basic_records, domain): 'basic',
            self._executor.submit(self.get_authoritative_records, domain): 'auth',
            self._executor.submit(self.analyze_spf, domain): 'spf',
            self._executor.submit(self.analyze_dmarc, domain): 'dmarc',
            self._executor.submit(self.analyze_dkim, domain, None, custom_dkim_selectors): 'dkim',
            self._executor.submit(self.analyze_mta_sts, domain): 'mta_sts',
            self._executor.submit(self.analyze_tlsrpt, domain): 'tlsrpt',
            self._executor.submit(self.analyze_bimi, domain): 'bimi',
            self._executor.submit(self.analyze_caa, domain): 'caa',
            self._executor.submit(self.analyze_dnssec, domain): 'dnssec',
            self._executor.submit(self.analyze_ns_delegation, domain): 'ns_delegation',
            self._executor.submit(self.get_registrar_info, domain): 'registrar',
            self._executor.submit(self.validate_resolver_consensus, domain): 'resolver_consensus',
            self._executor.submit(self.discover_subdomains, domain): 'ct_subdomains',
        }
        
        results_map = {}
        task_times = {}
        try:
            for future in as_completed(futures, timeout=35):
                key = futures[future]
                task_elapsed = round(time.time() - analysis_start, 2)
                task_times[key] = task_elapsed
                try:
                    results_map[key] = future.result()
                except Exception as e:
                    logging.error(f"Error in {key} lookup: {e}")
                    results_map[key] = {} if key in ['basic', 'auth'] else {'status': 'error'}
        except FuturesTimeoutError:
            logging.warning(f"Some lookups timed out for {domain}, continuing with partial results")
            for future, key in futures.items():
                if key not in results_map:
                    if future.done():
                        try:
                            results_map[key] = future.result()
                        except Exception:
                            results_map[key] = {} if key in ['basic', 'auth'] else {'status': 'error'}
                    else:
                        future.cancel()
                        logging.warning(f"Lookup {key} timed out for {domain}")
                        if key in ['basic', 'auth']:
                            results_map[key] = {}
                        elif key == 'ct_subdomains':
                            results_map[key] = {
                                'status': 'warning',
                                'message': 'Subdomain discovery exceeded time budget',
                                'source': 'Limited (timed out)',
                                'subdomains': [],
                                'unique_subdomains': 0,
                                'total_certs': 0,
                                'display_count': 0,
                                'current_count': 0,
                                'expired_count': 0,
                                'was_truncated': False,
                                'provider_summary': {},
                                'providers_found': 0,
                                'cname_count': 0,
                                'cname_discovered_count': 0,
                            }
                        else:
                            results_map[key] = {'status': 'timeout'}
        
        parallel_elapsed = round(time.time() - analysis_start, 2)
        sorted_tasks = sorted(task_times.items(), key=lambda x: x[1], reverse=True)
        slowest = ', '.join(f"{k}={v}s" for k, v in sorted_tasks[:5])
        logging.info(f"Parallel lookups for {domain} completed in {parallel_elapsed}s ({len(results_map)}/{len(futures)} tasks) | Slowest: {slowest}")
        
        basic = results_map.get('basic', {})
        auth = results_map.get('auth', {})
        auth_query_status = auth.pop('_query_status', {}) if isinstance(auth, dict) else {}
        resolver_ttl = basic.pop('_ttl', {}) if isinstance(basic, dict) else {}
        auth_ttl = auth.pop('_ttl', {}) if isinstance(auth, dict) else {}
        
        dane_start = time.time()
        mx_for_dane = basic.get('MX', [])
        dane_result = self.analyze_dane(domain, mx_for_dane)
        results_map['dane'] = dane_result
        dane_elapsed = round(time.time() - dane_start, 2)
        logging.info(f"DANE/TLSA check for {domain} completed in {dane_elapsed}s")
        
        dkim_result = results_map.get('dkim', {'status': 'error'})
        if isinstance(dkim_result, dict) and dkim_result.get('selectors'):
            mx_records = basic.get('MX', [])
            spf_data = results_map.get('spf', {})
            spf_valid = spf_data.get('valid_records', []) if isinstance(spf_data, dict) else []
            spf_record = spf_valid[0] if spf_valid else ''
            if mx_records or spf_record:
                provider_info = self._detect_primary_mail_provider(mx_records, spf_record)
                primary_provider = provider_info['provider']
                security_gateway = provider_info['gateway']
                found_providers = set()
                for sel_name, sel_data in dkim_result.get('selectors', {}).items():
                    p = sel_data.get('provider', 'Unknown')
                    if p != 'Unknown':
                        found_providers.add(p)
                
                primary_has_dkim = False
                unattributed_selectors = [
                    sel_name for sel_name, sel_data in dkim_result.get('selectors', {}).items()
                    if sel_data.get('provider', 'Unknown') == 'Unknown'
                ]
                if primary_provider != 'Unknown':
                    expected_selectors = self.PRIMARY_PROVIDER_SELECTORS.get(primary_provider, [])
                    if expected_selectors:
                        primary_has_dkim = any(s in dkim_result['selectors'] for s in expected_selectors)
                    else:
                        primary_has_dkim = primary_provider in found_providers
                    if not primary_has_dkim and unattributed_selectors:
                        primary_has_dkim = True
                        for sel_name in unattributed_selectors:
                            dkim_result['selectors'][sel_name]['provider'] = primary_provider
                            dkim_result['selectors'][sel_name]['inferred'] = True
                        found_providers.add(primary_provider)
                        inferred_names = ', '.join(s.replace('._domainkey', '') for s in unattributed_selectors)
                        dkim_result['primary_dkim_note'] = (
                            f'DKIM selector(s) {inferred_names} inferred as {primary_provider} '
                            f'(custom selector names \u2014 not the standard {primary_provider} selector).'
                        )
                
                dkim_result['primary_provider'] = primary_provider
                dkim_result['security_gateway'] = security_gateway
                dkim_result['primary_has_dkim'] = primary_has_dkim
                dkim_result['found_providers'] = list(sorted(found_providers))
                
                if dkim_result['selectors'] and primary_provider != 'Unknown' and not primary_has_dkim:
                    third_party_names = ', '.join(sorted(found_providers)) if found_providers else 'third-party services'
                    dkim_result['third_party_only'] = True
                    dkim_result['primary_dkim_note'] = (
                        f'DKIM verified for {third_party_names} only \u2014 '
                        f'no DKIM found for primary mail platform ({primary_provider}). '
                        f'The primary provider may use custom selectors not discoverable through standard checks.'
                    )
                    key_strengths = dkim_result.get('key_strengths', [])
                    dkim_result['status'] = 'partial'
                    if key_strengths:
                        dkim_result['message'] = f'Found DKIM for {len(dkim_result["selectors"])} selector(s) ({", ".join(set(key_strengths))}) but none for primary mail platform ({primary_provider})'
                    else:
                        dkim_result['message'] = f'Found DKIM for {len(dkim_result["selectors"])} selector(s) but none for primary mail platform ({primary_provider})'
                else:
                    dkim_result['third_party_only'] = False
                    if not dkim_result.get('primary_dkim_note'):
                        dkim_result['primary_dkim_note'] = ''
                
                results_map['dkim'] = dkim_result
        
        # Inject email security subdomain TXT records into basic_records for DNS Evidence Diff
        dmarc_data = results_map.get('dmarc', {})
        mta_sts_data = results_map.get('mta_sts', {})
        tlsrpt_data = results_map.get('tlsrpt', {})
        basic['DMARC'] = dmarc_data.get('valid_records', []) if isinstance(dmarc_data, dict) and dmarc_data.get('status') in ('success', 'warning') else []
        basic['MTA-STS'] = [mta_sts_data.get('record', '')] if isinstance(mta_sts_data, dict) and mta_sts_data.get('record') else []
        basic['TLS-RPT'] = [tlsrpt_data.get('record', '')] if isinstance(tlsrpt_data, dict) and tlsrpt_data.get('record') else []
        
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

        # Track section status for partial failure banners
        section_status = {}
        for key, result in results_map.items():
            if isinstance(result, dict):
                status = result.get('status', 'unknown')
                if status == 'timeout':
                    section_status[key] = {'status': 'timeout', 'message': 'Query timed out'}
                elif status == 'error':
                    section_status[key] = {'status': 'error', 'message': result.get('message', 'Lookup failed')}
                else:
                    section_status[key] = {'status': 'ok'}
            else:
                section_status[key] = {'status': 'ok'}
        
        results = {
            'domain_exists': True,
            'domain_status': domain_status,
            'domain_status_message': domain_status_message,
            'section_status': section_status,
            'basic_records': basic,
            'authoritative_records': auth,
            'auth_query_status': auth_query_status,
            'resolver_ttl': resolver_ttl,
            'auth_ttl': auth_ttl,
            'propagation_status': propagation_status,
            'spf_analysis': results_map.get('spf', {'status': 'error'}),
            'dmarc_analysis': results_map.get('dmarc', {'status': 'error'}),
            'dkim_analysis': results_map.get('dkim', {'status': 'error'}),
            'mta_sts_analysis': results_map.get('mta_sts', {'status': 'warning'}),
            'tlsrpt_analysis': results_map.get('tlsrpt', {'status': 'warning'}),
            'bimi_analysis': results_map.get('bimi', {'status': 'warning'}),
            'dane_analysis': results_map.get('dane', {'status': 'info', 'has_dane': False, 'tlsa_records': [], 'issues': []}),
            'caa_analysis': results_map.get('caa', {'status': 'warning'}),
            'dnssec_analysis': results_map.get('dnssec', {'status': 'warning'}),
            'ns_delegation_analysis': results_map.get('ns_delegation', {'status': 'warning'}),
            'registrar_info': results_map.get('registrar', {'status': 'error', 'registrar': None}),
            'resolver_consensus': results_map.get('resolver_consensus', {
                'consensus_reached': True,
                'resolvers_queried': 4,
                'checks_performed': 0,
                'discrepancies': [],
                'per_record_consensus': {}
            }),
            'ct_subdomains': results_map.get('ct_subdomains', {'status': 'error', 'subdomains': [], 'unique_subdomains': 0}),
        }
        
        # SMTP Transport verification disabled - port 25 blocked in production
        results['smtp_transport'] = None
        
        # Detect Null MX (RFC 7505): "MX 0 ." means domain explicitly does not accept mail
        mx_records = basic.get('MX', [])
        has_null_mx = any(
            r.strip().rstrip('.').replace(' ', '') in ['0.', '0'] or r.strip() == '0 .'
            for r in mx_records
        ) if mx_records else False
        results['has_null_mx'] = has_null_mx
        
        # Classify mail posture using graduated RFC-grounded model
        mail_posture = self._classify_mail_posture(results)
        results['mail_posture'] = mail_posture
        
        # Legacy compatibility: is_no_mail_domain used by posture scoring and verdicts
        spf = results.get('spf_analysis', {})
        dmarc = results.get('dmarc_analysis', {})
        is_no_mail_domain = mail_posture['classification'] in ('no_mail_verified', 'no_mail_partial')
        results['is_no_mail_domain'] = is_no_mail_domain
        
        if is_no_mail_domain:
            if dmarc.get('status') == 'error' and 'No valid DMARC' in dmarc.get('message', ''):
                results['dmarc_analysis'] = {
                    **dmarc,
                    'status': 'warning',
                    'message': 'No DMARC record - recommend adding v=DMARC1; p=reject; to complete anti-spoofing protection',
                    'no_mail_recommendation': True,
                    'suggested_record': 'v=DMARC1; p=reject;'
                }
            elif dmarc.get('policy') == 'reject':
                results['dmarc_analysis'] = {
                    **dmarc,
                    'message': 'DMARC policy reject - excellent anti-spoofing protection for non-mail domain'
                }
        
        # Add Hosting/Who summary
        results['hosting_summary'] = self.get_hosting_info(domain, results)
        
        # Add DNS Infrastructure analysis (enterprise security detection)
        results['dns_infrastructure'] = self.analyze_dns_infrastructure(domain, results)
        
        # Detect Email Security Management Stack (monitoring providers, SPF flattening)
        results['email_security_mgmt'] = self._detect_email_security_management(
            results.get('spf_analysis', {}),
            results.get('dmarc_analysis', {}),
            results.get('tlsrpt_analysis', {}),
            results.get('mta_sts_analysis', {}),
            domain=domain,
            dkim_analysis=results.get('dkim_analysis', {})
        )
        
        # Calculate Posture Score
        results['posture'] = self._calculate_posture(results)
        
        return results
    
    def _get_registered_domain(self, domain: str) -> Optional[str]:
        """Return the registered/base domain (eTLD+1) using the Public Suffix List.
        
        Per RFC 8499 (DNS Terminology), a subdomain is any domain that is
        a descendant of another domain in the DNS namespace hierarchy.
        The Public Suffix List (used by all major browsers) determines the
        boundary between registry-controlled labels and registrable domains.
        
        Returns None if the domain IS the registered domain (not a subdomain),
        or if tldextract is not available.
        """
        if not HAS_TLDEXTRACT:
            return None
        try:
            extracted = tldextract.extract(domain)
            if not extracted.domain or not extracted.suffix:
                return None
            registered = f"{extracted.domain}.{extracted.suffix}"
            if registered.lower() == domain.lower():
                return None
            return registered
        except Exception:
            return None

    def discover_subdomains(self, domain: str) -> Dict[str, Any]:
        """Discover subdomains via Certificate Transparency logs (crt.sh).
        
        Uses passive reconnaissance only - queries public CT log aggregator.
        No active scanning or brute-forcing. All data comes from publicly
        auditable certificate transparency logs per RFC 6962.
        
        When analyzing a subdomain, detects this via the Public Suffix List
        and annotates the result so the UI can suggest scanning the registered
        domain for broader subdomain enumeration.
        """
        registered_domain = self._get_registered_domain(domain)
        is_analyzed_subdomain = registered_domain is not None

        result = {
            'status': 'success',
            'source': 'Certificate Transparency Logs + DNS Probing',
            'source_url': 'https://crt.sh',
            'rfc': 'RFC 6962',
            'domain': domain,
            'subdomains': [],
            'total_certs': 0,
            'unique_subdomains': 0,
            'is_analyzed_subdomain': is_analyzed_subdomain,
            'registered_domain': registered_domain,
            'caveat': 'Combines CT log certificates (RFC 6962) with DNS probing of common service names. '
                      'Does not include internal-only names or uncommon subdomain prefixes.',
        }
        
        TOTAL_BUDGET = 30
        CT_TIMEOUT = 12
        ct_start = time.time()
        
        def _budget_remaining():
            return max(0, TOTAL_BUDGET - (time.time() - ct_start))
        
        subdomain_map = {}
        wildcard_certs = []
        ct_success = False
        
        cached_ct = self._get_ct_cache(domain)
        if cached_ct is not None:
            data = cached_ct
            result['total_certs'] = len(data)
            result['ct_source'] = 'cache'
            ct_success = True
            logging.info(f"CT cache hit for {domain}: {len(data)} certs")
        else:
            data = None
            try:
                ct_timeout = min(CT_TIMEOUT, _budget_remaining())
                if ct_timeout < 2:
                    raise requests.exceptions.Timeout("Insufficient time budget for CT query")
                
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                response = requests.get(url, timeout=ct_timeout, headers={
                    'User-Agent': self.USER_AGENT
                })
                
                if response.status_code == 200:
                    data = response.json()
                    result['total_certs'] = len(data)
                    ct_success = True
                    self._set_ct_cache(domain, data)
                    logging.info(f"CT query for {domain}: {len(data)} certs in {round(time.time() - ct_start, 1)}s")
                else:
                    logging.warning(f"CT log query for {domain} returned status {response.status_code}")
                    
            except requests.exceptions.Timeout:
                logging.warning(f"CT log query timed out for {domain} after {round(time.time() - ct_start, 1)}s — falling back to DNS probing")
            except requests.exceptions.ConnectionError:
                logging.warning(f"CT log connection failed for {domain} — falling back to DNS probing")
            except Exception as e:
                logging.warning(f"CT log query error for {domain}: {e} — falling back to DNS probing")
        
        if ct_success and data:
            CT_ENTRY_CAP = 5000
            entries_to_process = data[:CT_ENTRY_CAP] if len(data) > CT_ENTRY_CAP else data
            if len(data) > CT_ENTRY_CAP:
                logging.info(f"CT data for {domain} has {len(data)} entries, capping processing at {CT_ENTRY_CAP}")
            
            for entry in entries_to_process:
                names = set()
                cn = entry.get('common_name', '')
                if cn:
                    names.add(cn.lower().strip())
                name_value = entry.get('name_value', '')
                if name_value:
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name and '@' not in name:
                            names.add(name)
                
                not_before = entry.get('not_before', '')
                not_after = entry.get('not_after', '')
                issuer = entry.get('issuer_name', '')
                
                for name in names:
                    if name == f'*.{domain}':
                        issuer_cn = ''
                        if 'CN=' in issuer:
                            issuer_cn = issuer.split('CN=')[1].split(',')[0].strip()
                        wildcard_certs.append({
                            'name': name,
                            'not_before': not_before,
                            'not_after': not_after,
                            'issuer': issuer_cn,
                        })
                    
                    if name.endswith(f'.{domain}') or name == domain:
                        clean_name = name.lstrip('*.')
                        if clean_name == domain:
                            continue
                        
                        is_wildcard = name.startswith('*.')
                        
                        if clean_name not in subdomain_map:
                            subdomain_map[clean_name] = {
                                'name': clean_name,
                                'first_seen': not_before,
                                'last_seen': not_before,
                                'not_after': not_after,
                                'cert_count': 0,
                                'is_wildcard': is_wildcard,
                                'issuers': set(),
                            }
                        
                        entry_data = subdomain_map[clean_name]
                        entry_data['cert_count'] += 1
                        if not_before and (not entry_data['first_seen'] or not_before < entry_data['first_seen']):
                            entry_data['first_seen'] = not_before
                        if not_before and (not entry_data['last_seen'] or not_before > entry_data['last_seen']):
                            entry_data['last_seen'] = not_before
                        if not_after and (not entry_data['not_after'] or not_after > entry_data['not_after']):
                            entry_data['not_after'] = not_after
                        
                        issuer_cn = ''
                        if 'CN=' in issuer:
                            issuer_cn = issuer.split('CN=')[1].split(',')[0].strip()
                        if issuer_cn:
                            entry_data['issuers'].add(issuer_cn)
            
            logging.info(f"CT processing for {domain}: {len(subdomain_map)} unique subdomains from {len(entries_to_process)} entries")
        
        try:
            from datetime import datetime
            now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
            
            subdomains = []
            for name, data in subdomain_map.items():
                is_expired = data['not_after'] < now if data['not_after'] else True
                is_current = not is_expired
                
                subdomains.append({
                    'name': data['name'],
                    'first_seen': data['first_seen'][:10] if data['first_seen'] else '',
                    'last_seen': data['last_seen'][:10] if data['last_seen'] else '',
                    'cert_count': data['cert_count'],
                    'is_wildcard': data['is_wildcard'],
                    'is_current': is_current,
                    'issuers': sorted(list(data['issuers']))[:3],
                })
            
            has_current_wildcard = False
            if wildcard_certs:
                has_current_wildcard = any(
                    wc['not_after'] >= now for wc in wildcard_certs if wc.get('not_after')
                )
                result['wildcard_certs'] = {
                    'present': True,
                    'current': has_current_wildcard,
                    'count': len(wildcard_certs),
                    'pattern': f'*.{domain}',
                }
            
            if _budget_remaining() > 3:
                dns_found = self._probe_common_subdomains(domain)
                for sub_name in dns_found:
                    if sub_name not in subdomain_map:
                        subdomains.append({
                            'name': sub_name,
                            'first_seen': '',
                            'last_seen': '',
                            'cert_count': 0,
                            'is_wildcard': False,
                            'is_current': True,
                            'issuers': [],
                            'source': 'dns',
                        })
                logging.info(f"DNS probing for {domain}: {len(dns_found)} found, budget remaining: {round(_budget_remaining(), 1)}s")
            else:
                logging.warning(f"Skipping DNS probing for {domain} — insufficient time budget ({round(_budget_remaining(), 1)}s remaining)")
            
            total_count = len(subdomains)
            current_count = sum(1 for s in subdomains if s['is_current'])
            expired_count = total_count - current_count
            
            DISPLAY_LIMIT = 100
            
            all_known_names = {s['name'] for s in subdomains}
            
            display_set, was_truncated = self._curate_subdomain_display(
                subdomains, domain, limit=DISPLAY_LIMIT
            )
            
            provider_summary = {}
            cname_discovered = []
            cname_budget = _budget_remaining()
            if cname_budget > 3 and display_set:
                provider_summary, cname_discovered = self._enrich_subdomains_with_cnames(
                    display_set, domain, all_known_names, timeout=min(cname_budget - 1, 10)
                )
                
                if cname_discovered:
                    existing_names = {s['name'] for s in display_set}
                    for cname_sub in cname_discovered:
                        if cname_sub['name'] not in existing_names:
                            prefix = cname_sub['name'].replace(f'.{domain}', '').split('.')[0] if cname_sub['name'].endswith(f'.{domain}') else cname_sub['name'].split('.')[0]
                            cname_sub['_priority'] = prefix.lower() in self.SECURITY_RELEVANT_PREFIXES
                            display_set.append(cname_sub)
                            existing_names.add(cname_sub['name'])
                    total_count += len(cname_discovered)
                    current_count += sum(1 for s in cname_discovered if s['is_current'])
                    logging.info(f"CNAME discovery added {len(cname_discovered)} new subdomains for {domain}")
            else:
                logging.warning(f"Skipping CNAME enrichment for {domain} — insufficient time budget ({round(cname_budget, 1)}s remaining)")
            
            display_set.sort(key=lambda x: (
                not x['is_current'],
                not bool(x.get('provider')),
                not x.get('_priority', False),
                x.get('source') != 'cname',
                -x['cert_count'],
                x['name']
            ))
            
            if not ct_success and not subdomains:
                result['status'] = 'info'
                result['message'] = 'Subdomain discovery services were unavailable — no subdomains found via CT logs or DNS probing'
                result['source'] = 'Limited (services unavailable)'
            elif not ct_success and subdomains:
                result['status'] = 'warning'
                result['message'] = 'CT log service was slow or unavailable — showing DNS-probed subdomains only'
                result['source'] = 'DNS Probing (CT logs unavailable)'
            
            result['subdomains'] = display_set
            result['unique_subdomains'] = total_count
            result['display_count'] = len(display_set)
            result['current_count'] = current_count
            result['expired_count'] = expired_count
            result['was_truncated'] = was_truncated
            result['provider_summary'] = provider_summary
            result['providers_found'] = len(provider_summary)
            result['cname_count'] = sum(1 for s in display_set if s.get('cname_chain'))
            result['cname_discovered_count'] = len(cname_discovered) if cname_discovered else 0
            
            elapsed = round(time.time() - ct_start, 1)
            logging.info(f"Subdomain discovery for {domain} completed in {elapsed}s (CT: {'ok' if ct_success else 'failed'}, {total_count} subdomains, {len(provider_summary)} providers)")
            
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f'Subdomain discovery failed: {str(e)}'
            logging.error(f"Subdomain discovery error for {domain}: {e}")
        
        return result
    
    SECURITY_RELEVANT_PREFIXES = frozenset([
        'www', 'mail', 'email', 'webmail', 'smtp', 'imap', 'pop', 'pop3',
        'mx', 'mx1', 'mx2', 'relay', 'mta',
        'api', 'api2', 'app', 'admin', 'portal', 'dashboard', 'console',
        'vpn', 'remote', 'sso', 'auth', 'login', 'signin', 'oauth', 'id', 'identity', 'accounts',
        'autodiscover', 'autoconfig', 'lyncdiscover', 'sip',
        'owa', 'exchange', 'outlook', 'sharepoint',
        'ftp', 'sftp', 'ssh', 'bastion',
        'ns1', 'ns2', 'ns3', 'ns4', 'dns',
        'dev', 'staging', 'beta', 'test',
        'cdn', 'static', 'assets', 'media',
        'git', 'gitlab', 'ci',
        'status', 'monitor', 'grafana', 'sentry',
        'blog', 'shop', 'store', 'docs', 'help', 'support', 'kb',
        'crm', 'erp', 'jira', 'confluence',
        'pay', 'payment', 'checkout', 'billing',
        'cloud', 'server', 'proxy', 'gateway', 'lb', 'waf',
        'secure', 'security', 'firewall',
        'intranet', 'corp', 'office', 'internal',
        'zendesk', 'hubspot', 'salesforce',
        'm', 'mobile',
        'calendar', 'meet', 'chat', 'teams', 'zoom',
    ])

    def _curate_subdomain_display(self, subdomains: list, domain: str, limit: int = 100) -> tuple:
        """Select the most security-relevant subdomains for display.
        
        Uses a priority scoring system to surface subdomains that matter most
        for security analysis while keeping the report concise and actionable.
        
        Returns (display_list, was_truncated) tuple.
        """
        if len(subdomains) <= limit:
            return subdomains, False
        
        for sub in subdomains:
            prefix = sub['name'].replace(f'.{domain}', '').split('.')[0] if sub['name'].endswith(f'.{domain}') else sub['name'].split('.')[0]
            sub['_priority'] = prefix.lower() in self.SECURITY_RELEVANT_PREFIXES
            sub['_source_dns'] = sub.get('source') == 'dns'
        
        current_priority = [s for s in subdomains if s['is_current'] and s['_priority']]
        current_dns_only = [s for s in subdomains if s['is_current'] and s['_source_dns'] and not s['_priority']]
        current_other = [s for s in subdomains if s['is_current'] and not s['_priority'] and not s['_source_dns']]
        expired_priority = [s for s in subdomains if not s['is_current'] and s['_priority']]
        expired_other = [s for s in subdomains if not s['is_current'] and not s['_priority']]
        
        current_priority.sort(key=lambda x: (-x['cert_count'], x['name']))
        current_dns_only.sort(key=lambda x: x['name'])
        current_other.sort(key=lambda x: (-x['cert_count'], x['name']))
        expired_priority.sort(key=lambda x: (-x['cert_count'], x['name']))
        expired_other.sort(key=lambda x: (-x['cert_count'], x['name']))
        
        display = []
        remaining = limit
        
        for tier in [current_priority, current_dns_only, current_other, expired_priority, expired_other]:
            take = min(len(tier), remaining)
            display.extend(tier[:take])
            remaining -= take
            if remaining <= 0:
                break
        
        logging.info(f"Subdomain curation for {domain}: {len(subdomains)} total -> {len(display)} displayed "
                     f"(priority={len(current_priority)}, dns={len(current_dns_only)}, "
                     f"other_current={len(current_other)}, expired_priority={len(expired_priority)})")
        
        return display, True

    def _resolve_cname_chain(self, fqdn: str, max_depth: int = 8) -> dict:
        """Resolve the full CNAME chain for a given FQDN.
        
        Returns dict with:
          - chain: list of CNAME targets in order
          - target: final CNAME target (or None if no CNAME)
          - provider: identified provider dict or None
        """
        chain = []
        seen = set()
        current = fqdn
        
        r = dns.resolver.Resolver()
        r.nameservers = ['1.1.1.1', '8.8.8.8']
        r.lifetime = 2.0
        r.timeout = 1.5
        
        for _ in range(max_depth):
            if current in seen:
                break
            seen.add(current)
            try:
                answers = r.resolve(current, 'CNAME')
                for rdata in answers:
                    target = str(rdata.target).rstrip('.')
                    chain.append(target)
                    current = target
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                break
            except Exception:
                break
        
        provider = None
        for cname_target in reversed(chain):
            provider = self._identify_cname_provider(cname_target)
            if provider:
                break
        
        return {
            'chain': chain,
            'target': chain[-1] if chain else None,
            'provider': provider,
        }

    def _identify_cname_provider(self, cname_target: str) -> Optional[dict]:
        """Match a CNAME target against known SaaS/cloud provider patterns."""
        target_lower = cname_target.lower()
        for pattern, info in self.CNAME_PROVIDER_MAP.items():
            if target_lower == pattern or target_lower.endswith('.' + pattern):
                return info
        return None

    def _enrich_subdomains_with_cnames(self, subdomains: list, domain: str = None, all_known_names: set = None, timeout: float = 10) -> tuple:
        """Resolve CNAME chains for all discovered subdomains in parallel.
        
        Returns (provider_summary, cname_discovered) tuple:
          - provider_summary: dict counting providers by category
          - cname_discovered: list of new subdomains found as intermediate
            CNAME hops within the analyzed domain (source='cname')
        
        Also mutates each subdomain dict to add cname_chain, cname_target, provider keys.
        
        When domain is provided, intermediate CNAME chain hops that are subdomains
        of that domain get collected as newly discovered subdomains. This makes CNAME
        resolution a third discovery method alongside CT logs and DNS probing.
        
        all_known_names should include ALL discovered subdomain names (pre-curation),
        not just the display set, to prevent re-discovering subdomains that were
        already found by CT/DNS but excluded during curation.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        current_subs = [s for s in subdomains if s.get('is_current', False)]
        known_names = all_known_names if all_known_names else {s['name'] for s in subdomains}
        
        def resolve_one(sub):
            name = sub['name']
            result = self._resolve_cname_chain(name)
            return (name, result)
        
        cname_results = {}
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(resolve_one, s): s for s in current_subs}
            try:
                for future in as_completed(futures, timeout=timeout):
                    try:
                        name, result = future.result(timeout=3)
                        cname_results[name] = result
                    except Exception:
                        continue
            except TimeoutError:
                for future in futures:
                    if future.done():
                        try:
                            name, result = future.result(timeout=0)
                            cname_results[name] = result
                        except Exception:
                            continue
        
        provider_summary = {}
        cname_discovered = {}
        domain_suffix = f'.{domain}' if domain else None
        
        for sub in subdomains:
            cname_data = cname_results.get(sub['name'])
            if cname_data and cname_data['chain']:
                sub['cname_chain'] = cname_data['chain']
                sub['cname_target'] = cname_data['target']
                if cname_data['provider']:
                    sub['provider'] = cname_data['provider']['name']
                    sub['provider_category'] = cname_data['provider']['category']
                    cat = cname_data['provider']['category']
                    pname = cname_data['provider']['name']
                    if pname not in provider_summary:
                        provider_summary[pname] = {'name': pname, 'category': cat, 'count': 0, 'subdomains': []}
                    provider_summary[pname]['count'] += 1
                    provider_summary[pname]['subdomains'].append(sub['name'])
                
                if domain_suffix:
                    for hop in cname_data['chain']:
                        hop_lower = hop.lower()
                        if hop_lower.endswith(domain_suffix) and hop_lower != domain and hop_lower not in known_names and hop_lower not in cname_discovered:
                            cname_discovered[hop_lower] = {
                                'name': hop_lower,
                                'first_seen': '',
                                'last_seen': '',
                                'cert_count': 0,
                                'is_wildcard': False,
                                'is_current': True,
                                'issuers': [],
                                'source': 'cname',
                                'discovered_via': sub['name'],
                            }
        
        cname_discovered_list = list(cname_discovered.values())
        logging.info(f"CNAME enrichment: resolved {len(cname_results)} subdomains, identified {len(provider_summary)} providers, discovered {len(cname_discovered_list)} new subdomains via CNAME chains")
        return provider_summary, cname_discovered_list

    def _probe_common_subdomains(self, domain: str) -> list:
        """Probe common subdomain names via DNS A/AAAA lookups.
        
        Complements CT log discovery by resolving ~290 common service names
        that businesses actually use. CT logs only find subdomains with TLS
        certificates; DNS probing finds subdomains that resolve but may lack
        certificates (e.g., CNAME to SaaS providers, internal services).
        
        Categories covered: web, mail, DNS infrastructure, development/CI,
        collaboration (Microsoft 365, Google Workspace, Zoom, etc.), databases,
        monitoring, authentication, e-commerce/payments, VoIP/telephony,
        file storage, learning/training, marketing/analytics, SaaS platforms
        (Zendesk, HubSpot, Salesforce, Zoho), events/booking, careers,
        and international variants (correo, posta, tienda, etc.).
        
        Only resolves names — no active scanning or brute-forcing beyond
        the curated list of common service names.
        """
        common_prefixes = [
            'www', 'www2', 'www3', 'web', 'web1', 'web2', 'web3',
            'mail', 'mail2', 'mail3', 'email', 'webmail', 'smtp', 'smtp2', 'imap', 'pop', 'pop3',
            'mx', 'mx1', 'mx2', 'mx3', 'relay', 'mta',
            'ftp', 'sftp', 'ssh', 'vpn', 'vpn2', 'remote', 'rdp', 'bastion',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
            'api', 'api2', 'app', 'app2', 'dev', 'dev2', 'staging', 'stage', 'test', 'beta', 'demo', 'sandbox', 'uat', 'qa',
            'admin', 'panel', 'cpanel', 'whm', 'dashboard', 'portal', 'console', 'manage', 'manager',
            'blog', 'shop', 'store', 'boutique', 'docs', 'wiki', 'help', 'support', 'kb', 'faq',
            'cdn', 'static', 'assets', 'media', 'img', 'images', 'video', 'streaming',
            'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'elasticsearch',
            'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'cd', 'build', 'deploy', 'registry', 'docker', 'repo', 'artifacts',
            'jira', 'confluence', 'trello', 'asana', 'notion',
            'status', 'monitor', 'monitoring', 'grafana', 'prometheus', 'kibana', 'sentry', 'alerts', 'logs', 'logging',
            'auth', 'login', 'signin', 'signup', 'sso', 'id', 'identity', 'oauth', 'accounts',
            'calendar', 'cal', 'meet', 'meeting', 'meetings', 'chat', 'slack', 'teams', 'zoom', 'webex',
            'cloud', 'server', 'server1', 'server2', 'host', 'host1', 'host2', 'node', 'node1', 'cluster',
            'intranet', 'internal', 'office', 'corp', 'corporate', 'extranet',
            'm', 'mobile', 'wap',
            'autodiscover', 'autoconfig', 'lyncdiscover', 'sip', 'sipfed',
            'owa', 'exchange', 'outlook', 'sharepoint', 'onedrive', 'lync', 'skype',
            'backup', 'bak', 'old', 'legacy', 'archive',
            'schedule', 'scheduling', 'booking', 'book', 'reserve', 'appointments',
            'screen', 'proxy', 'gateway', 'gw', 'lb', 'loadbalancer', 'cache', 'waf',
            'crm', 'erp', 'hr', 'finance', 'billing', 'invoice', 'invoices', 'accounting',
            'pay', 'payment', 'payments', 'checkout', 'orders', 'cart',
            'voip', 'pbx', 'phone', 'tel', 'sbc', 'fax',
            'print', 'printer', 'scan', 'nas', 'storage', 'files', 'file', 'share', 'download', 'upload', 'drive',
            'learn', 'learning', 'lms', 'training', 'academy', 'courses', 'edu', 'education', 'classroom', 'moodle',
            'analytics', 'tracking', 'stats', 'marketing', 'newsletter', 'campaigns', 'ads',
            'zendesk', 'hubspot', 'salesforce', 'zoho', 'freshdesk',
            'forum', 'community', 'social', 'press', 'news', 'updates',
            'events', 'tickets', 'webinar', 'register', 'registration', 'rsvp',
            'careers', 'jobs', 'hiring', 'recruit', 'talent',
            'survey', 'feedback', 'reviews', 'forms',
            'maps', 'location', 'locations', 'directory',
            'secure', 'security', 'firewall', 'ids',
            'new', 'preview', 'next', 'launch', 'go',
            'reports', 'reporting', 'data', 'bi', 'tableau',
            'correo', 'posta', 'webshop', 'tienda', 'magasin',
            'link', 'links', 'url', 'redirect', 'r',
            'ws', 'socket', 'realtime', 'push', 'notify', 'notifications',
        ]
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        found = []
        
        def make_resolver():
            r = dns.resolver.Resolver()
            r.nameservers = ['1.1.1.1', '8.8.8.8']
            r.lifetime = 1.5
            r.timeout = 1.0
            return r
        
        wildcard_ips = set()
        try:
            r = make_resolver()
            answers = r.resolve(f'unlikely-random-xz9q7w.{domain}', 'A')
            for rdata in answers:
                wildcard_ips.add(str(rdata))
        except Exception:
            pass
        
        def probe_one(prefix):
            fqdn = f'{prefix}.{domain}'
            try:
                r = make_resolver()
                answers = r.resolve(fqdn, 'A')
                resolved_ips = {str(rdata) for rdata in answers}
                if wildcard_ips and resolved_ips == wildcard_ips:
                    return None
                return fqdn
            except Exception:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(probe_one, p): p for p in common_prefixes}
            try:
                for future in as_completed(futures, timeout=15):
                    try:
                        fqdn = future.result(timeout=3)
                        if fqdn:
                            found.append(fqdn)
                    except Exception:
                        continue
            except TimeoutError:
                for future in futures:
                    if future.done():
                        try:
                            fqdn = future.result(timeout=0)
                            if fqdn:
                                found.append(fqdn)
                        except Exception:
                            continue
        
        logging.info(f"DNS subdomain probing for {domain}: found {len(found)} subdomains, wildcard_ips={wildcard_ips or 'none'}")
        return found

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
                            if not_after and isinstance(not_after, str):
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
    
    def analyze_smtp_transport(self, domain: str, mx_records: Optional[List[str]] = None) -> Dict[str, Any]:
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
    
    def _classify_mail_posture(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Classify domain's mail posture using a graduated RFC-grounded model.
        
        Returns a structured assessment of whether the domain intends to send/receive
        email, based on observable DNS signals. Each signal is individually evaluated
        and the overall classification is derived from the combination.
        
        Classifications:
          - no_mail_verified:  All three layers configured (Null MX + SPF -all + DMARC reject)
          - no_mail_partial:   Some no-mail signals present but gaps remain
          - email_ambiguous:   Signals are inconsistent or insufficient to determine intent
          - email_enabled:     Domain has active mail infrastructure
        
        RFC basis:
          - RFC 7505: Null MX (explicit inbound refusal)
          - RFC 7208: SPF (sender authorization, -all = no senders)
          - RFC 7489: DMARC (policy enforcement)
          - RFC 5321 §5.1: MX fallback to A/AAAA (why "no MX" ≠ "no mail")
        """
        spf = results.get('spf_analysis', {})
        dmarc = results.get('dmarc_analysis', {})
        mx_records = results.get('basic_records', {}).get('MX', [])
        has_null_mx = results.get('has_null_mx', False)
        
        spf_deny_all = spf.get('no_mail_intent', False)
        spf_status = spf.get('status', '')
        spf_permissiveness = spf.get('permissiveness', '')
        
        dmarc_policy = (dmarc.get('policy') or '').lower()
        dmarc_status = dmarc.get('status', '')
        has_dmarc = dmarc_status in ('success', 'warning', 'info') or bool(dmarc_policy)
        dmarc_reject = dmarc_policy == 'reject'
        dmarc_quarantine = dmarc_policy == 'quarantine'
        
        has_mx = len(mx_records) > 0 and not has_null_mx
        has_senders = (
            bool(spf.get('includes')) or
            bool(spf.get('lookup_mechanisms')) or
            spf_permissiveness in ('DANGEROUS', 'NEUTRAL') or
            (spf_status == 'success' and not spf_deny_all and spf_permissiveness in ('SOFT', 'STRICT'))
        )
        
        signals = {
            'null_mx': {
                'present': has_null_mx,
                'rfc': 'RFC 7505',
                'rfc_url': 'https://datatracker.ietf.org/doc/html/rfc7505',
                'label': 'Null MX',
                'description': 'Explicitly refuses inbound mail delivery',
                'missing_risk': 'Without Null MX, SMTP servers may still attempt delivery via A/AAAA fallback (RFC 5321 §5.1)'
            },
            'spf_deny_all': {
                'present': spf_deny_all,
                'rfc': 'RFC 7208',
                'rfc_url': 'https://datatracker.ietf.org/doc/html/rfc7208',
                'label': 'SPF v=spf1 -all',
                'description': 'Declares no servers are authorized to send email',
                'missing_risk': 'Without SPF -all, attackers can send email appearing to come from this domain'
            },
            'dmarc_reject': {
                'present': dmarc_reject,
                'rfc': 'RFC 7489',
                'rfc_url': 'https://datatracker.ietf.org/doc/html/rfc7489',
                'label': 'DMARC p=reject',
                'description': 'Instructs receivers to reject spoofed messages',
                'missing_risk': 'Without DMARC reject, spoofed messages may still reach inboxes even with SPF -all'
            }
        }
        
        present_count = sum(1 for s in signals.values() if s['present'])
        
        missing_steps = []
        for key, sig in signals.items():
            if not sig['present']:
                missing_steps.append({
                    'control': sig['label'],
                    'rfc': sig['rfc'],
                    'rfc_url': sig['rfc_url'],
                    'action': sig['description'],
                    'risk': sig['missing_risk']
                })
        
        if present_count == 3:
            classification = 'no_mail_verified'
            label = 'No-Mail: Verified'
            color = 'success'
            icon = 'shield-alt'
            summary = 'This domain is fully hardened against email abuse. All three layers of no-mail protection are configured per RFC best practices.'
        elif present_count >= 1 and (spf_deny_all or has_null_mx) and not has_senders:
            classification = 'no_mail_partial'
            label = 'No-Mail: Partial'
            color = 'warning'
            icon = 'exclamation-triangle'
            if spf_deny_all and not has_null_mx and not dmarc_reject:
                summary = 'Outbound email is blocked (SPF -all), but inbound mail delivery is still possible via A/AAAA fallback (RFC 5321 §5.1) and spoofed messages may still reach inboxes.'
            elif spf_deny_all and not has_null_mx and dmarc_reject:
                summary = 'Outbound email is blocked and spoofed messages will be rejected, but inbound mail delivery is still possible via A/AAAA fallback (RFC 5321 §5.1).'
            elif spf_deny_all and has_null_mx and not dmarc_reject:
                summary = 'Inbound and outbound email are both blocked, but DMARC reject is missing — spoofed messages may still be delivered by receivers that don\'t check SPF.'
            elif has_null_mx and not spf_deny_all:
                summary = 'Inbound mail is explicitly refused (Null MX), but outbound spoofing is not fully prevented. Add SPF -all and DMARC reject to complete protection.'
            else:
                summary = 'Some no-mail signals are configured, but gaps remain. Complete all three layers for full protection.'
        elif not has_mx and not has_senders and spf_status != 'success':
            classification = 'email_ambiguous'
            label = 'Email: Ambiguous'
            color = 'secondary'
            icon = 'question-circle'
            summary = 'No mail infrastructure detected, but no explicit no-mail declarations either. Without Null MX (RFC 7505), SMTP servers fall back to A/AAAA records (RFC 5321 §5.1), meaning mail delivery may still be attempted. This domain\'s email intent is unclear.'
        elif has_mx and has_senders:
            classification = 'email_enabled'
            label = 'Email: Enabled'
            color = 'info'
            icon = 'envelope'
            summary = 'This domain has active mail infrastructure with MX records and authorized senders.'
        elif has_mx and not has_senders:
            classification = 'email_enabled'
            label = 'Email: Enabled (Inbound Only)'
            color = 'info'
            icon = 'envelope'
            summary = 'This domain accepts inbound mail but has no authorized outbound senders in SPF.'
        elif not has_mx and has_senders:
            classification = 'email_ambiguous'
            label = 'Email: Ambiguous'
            color = 'secondary'
            icon = 'question-circle'
            summary = 'SPF authorizes senders but no MX records exist. This domain may send email but cannot receive it reliably. Configuration is inconsistent.'
        else:
            classification = 'email_ambiguous'
            label = 'Email: Ambiguous'
            color = 'secondary'
            icon = 'question-circle'
            summary = 'Insufficient DNS signals to determine this domain\'s email intent.'
        
        recommended_record = None
        if classification in ('no_mail_partial', 'email_ambiguous') and not has_senders and not has_mx:
            parts = []
            if not has_null_mx:
                parts.append('Add MX record: 0 . (Null MX per RFC 7505)')
            if not spf_deny_all:
                parts.append('Add TXT record: v=spf1 -all')
            if not dmarc_reject:
                parts.append('Add TXT record at _dmarc: v=DMARC1; p=reject;')
            recommended_record = parts
        
        return {
            'classification': classification,
            'label': label,
            'color': color,
            'icon': icon,
            'summary': summary,
            'signals': signals,
            'present_count': present_count,
            'total_signals': 3,
            'missing_steps': missing_steps,
            'recommended_records': recommended_record,
            'is_no_mail': classification in ('no_mail_verified', 'no_mail_partial'),
        }

    def _calculate_posture(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall DNS & Trust Posture based on security controls."""
        issues = []  # Critical problems that need action
        monitoring_items = []  # Controls in monitoring/non-enforce mode
        configured_items = []  # Runtime-dependent controls that are present
        absent_items = []  # Optional controls not configured
        
        # Check if this is a "no-mail domain" (SPF -all only + no MX)
        is_no_mail_domain = results.get('is_no_mail_domain', False)
        
        # Check DMARC policy (DNS-verifiable enforcement level)
        dmarc = results.get('dmarc_analysis', {})
        dmarc_policy = (dmarc.get('policy') or '').lower()
        dmarc_status = dmarc.get('status', '')
        
        if dmarc_status == 'error' or (dmarc_status not in ('success', 'warning', 'info') and not dmarc_policy):
            # No DMARC record at all
            if is_no_mail_domain and dmarc.get('no_mail_recommendation'):
                # No-mail domain: DMARC missing is a recommendation, not critical issue
                monitoring_items.append('DMARC p=reject recommended to complete anti-spoofing protection')
            else:
                issues.append('No DMARC policy (email can be spoofed)')
        elif dmarc_policy == 'none':
            # DMARC exists but p=none provides NO enforcement - spoofed mail still delivered
            issues.append('DMARC p=none (monitoring only) - spoofed emails still reach inboxes')
        elif dmarc_policy == 'quarantine':
            monitoring_items.append('DMARC quarantine (p=reject recommended for full enforcement)')
        elif dmarc_status == 'success':
            # DMARC with reject policy - good!
            configured_items.append('DMARC (email spoofing protection)')
        
        # Check SPF
        spf = results.get('spf_analysis', {})
        if spf.get('status') != 'success':
            issues.append('No SPF record (no sender verification)')
        elif spf.get('no_mail_intent'):
            # SPF -all is intentional for no-mail domains - this is a security feature
            configured_items.append('SPF (no mail allowed - domain declares it sends no email)')
        
        dkim = results.get('dkim_analysis', {})
        dkim_status = dkim.get('status')
        dkim_selectors = dkim.get('selectors', {})
        dkim_third_party_only = dkim.get('third_party_only', False)
        dkim_has_inferred = any(
            sel_data.get('inferred') for sel_data in dkim_selectors.values()
        )
        if dkim_status == 'success' and dkim_selectors:
            key_strengths = dkim.get('key_strengths', [])
            if key_strengths:
                configured_items.append(f'DKIM ({len(dkim_selectors)} selector(s), {", ".join(key_strengths)})')
            else:
                configured_items.append(f'DKIM ({len(dkim_selectors)} selector(s) verified)')
        elif dkim_status == 'partial' and dkim_third_party_only:
            primary = dkim.get('primary_provider', 'primary platform')
            found_provs = dkim.get('found_providers', [])
            third_party_names = ', '.join(found_provs) if found_provs else 'third-party'
            monitoring_items.append(f'DKIM ({third_party_names} only \u2014 not verified for {primary})')
        elif dkim_status == 'warning':
            key_issues = dkim.get('key_issues', [])
            if any('revoked' in i.lower() for i in key_issues):
                monitoring_items.append('DKIM (some keys revoked)')
            elif any('1024' in i for i in key_issues):
                monitoring_items.append('DKIM (weak 1024-bit keys, upgrade to 2048)')
        
        # Check DNSSEC (DNS-verifiable)
        # Note: Unsigned DNSSEC is a deliberate design choice for many large operators
        # (Apple, Google, CDNs) who secure at other layers. Only broken chain is an issue.
        dnssec = results.get('dnssec_analysis', {})
        chain = dnssec.get('chain_of_trust', 'none')
        if chain == 'broken':
            issues.append('DNSSEC chain incomplete (DS record missing at registrar)')
        elif dnssec.get('status') == 'success':
            if chain == 'inherited':
                configured_items.append('DNSSEC (inherited from parent zone)')
            else:
                configured_items.append('DNSSEC (DNS responses signed)')
        else:
            # Unsigned is tracked as "not configured" - a design choice, not an error
            absent_items.append('DNSSEC (DNS response signing)')
        
        has_dnssec = dnssec.get('status') == 'success'
        
        # Check DANE/TLSA (RFC 6698, RFC 7672) - advanced email transport security
        # DANE's security guarantees depend on DNSSEC; without it, TLSA records can be spoofed
        dane = results.get('dane_analysis', {})
        has_mta_sts_configured = results.get('mta_sts_analysis', {}).get('status') == 'success'
        dane_deployable = dane.get('dane_deployable', True)
        dane_mx_provider = dane.get('mx_provider', {})
        if dane.get('has_dane'):
            if has_dnssec and dane.get('status') == 'success':
                if has_mta_sts_configured:
                    configured_items.append(f"DANE/TLSA ({dane.get('mx_hosts_with_dane', 0)} MX host(s) with TLSA records, DNSSEC-validated)")
                    configured_items.append('Dual transport security: DANE (cryptographic) + MTA-STS (HTTPS-based) — strongest posture')
                else:
                    configured_items.append(f"DANE/TLSA ({dane.get('mx_hosts_with_dane', 0)} MX host(s) with TLSA records, DNSSEC-validated) — strongest cryptographic transport security")
            elif dane.get('has_dane') and not has_dnssec:
                monitoring_items.append(f"DANE/TLSA records present but DNSSEC not validated — DANE requires DNSSEC for security (RFC 7672 §1.3)")
            elif dane.get('status') == 'warning':
                monitoring_items.append(f"DANE partial ({dane.get('mx_hosts_with_dane', 0)}/{dane.get('mx_hosts_checked', 0)} MX hosts)")
        elif not is_no_mail_domain:
            if not dane_deployable and dane_mx_provider:
                provider_name = dane_mx_provider.get('provider_name', 'hosted provider')
                if has_mta_sts_configured:
                    pass
                else:
                    absent_items.append(f'DANE not available on {provider_name} — deploy MTA-STS as the recommended transport security alternative')
            else:
                absent_items.append('DANE/TLSA (certificate pinning for mail transport)')
        
        # Check NS delegation
        ns_del = results.get('ns_delegation_analysis', {})
        if ns_del.get('delegation_ok') == False:
            issues.append('NS delegation issue (DNS may not resolve correctly)')
        
        # Check CAA (DNS-verifiable) - optional hardening, not core security
        caa = results.get('caa_analysis', {})
        if caa.get('status') == 'success':
            configured_items.append('CAA (certificate issuance restricted)')
        else:
            # CAA is recommended but not required - don't treat as issue
            absent_items.append('CAA (certificate authority control)')
        
        # Check MTA-STS (runtime-dependent - record presence only)
        mta_sts = results.get('mta_sts_analysis', {})
        if mta_sts.get('status') == 'success':
            configured_items.append('MTA-STS (policy present)')
        elif not is_no_mail_domain:
            absent_items.append('MTA-STS (email TLS policy)')
        
        # Check TLS-RPT (runtime-dependent - record presence only)
        tls_rpt = results.get('tlsrpt_analysis', {})  # Note: key is 'tlsrpt_analysis' not 'tls_rpt_analysis'
        if tls_rpt.get('status') == 'success':
            configured_items.append('TLS-RPT (reporting configured)')
        elif not is_no_mail_domain:
            absent_items.append('TLS-RPT (TLS delivery reporting)')
        
        # Check BIMI (runtime-dependent - record presence only)
        bimi = results.get('bimi_analysis', {})
        if bimi.get('status') == 'success':
            configured_items.append('BIMI (brand logo configured)')
        elif not is_no_mail_domain:
            absent_items.append('BIMI (brand logo in inboxes)')
        
        # Determine posture state
        # SECURE = all controls enforced INCLUDING DNSSEC
        # STRONG = excellent email controls but no DNSSEC (valid design choice)
        # PARTIAL = some controls missing
        # AT RISK = critical gaps
        if not issues and not monitoring_items:
            if has_dnssec and is_no_mail_domain:
                state = 'SECURE'
                color = 'success'
                icon = 'shield-alt'
                message = 'Non-mail domain fully secured. Anti-spoofing and DNSSEC enforced.'
            elif has_dnssec:
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
        
        # Detect deliberate monitoring posture:
        # When a domain deploys advanced cryptographic controls (DNSSEC + DANE validated)
        # alongside DMARC with reporting but p=none, this pattern suggests intentional
        # measurement/research posture rather than oversight or negligence.
        deliberate_monitoring = False
        deliberate_monitoring_note = None
        if (has_dnssec
                and dane.get('has_dane') and dane.get('status') == 'success'
                and dmarc_policy == 'none'
                and (dmarc.get('rua') or dmarc.get('ruf'))):
            deliberate_monitoring = True
            deliberate_monitoring_note = (
                'This domain deploys DNSSEC and DANE (advanced cryptographic transport security) '
                'alongside DMARC monitoring with active reporting — a combination that suggests '
                'deliberate measurement posture rather than misconfiguration. '
                'Some operators (standards bodies, research institutions) intentionally maintain '
                'p=none to observe ecosystem behavior without disrupting legacy or experimental mail flows.'
            )
        
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
            'deliberate_monitoring': deliberate_monitoring,
            'deliberate_monitoring_note': deliberate_monitoring_note,
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
        
        dkim_analysis = results.get('dkim_analysis', {})
        dkim_strong = dkim_analysis.get('status') == 'success' and dkim_analysis.get('key_strengths')
        dkim_third_party_only = dkim_analysis.get('third_party_only', False)
        dkim_primary_provider = dkim_analysis.get('primary_provider', '')
        
        dkim_has_inferred = any(
            sel_data.get('inferred') for sel_data in dkim_analysis.get('selectors', {}).values()
        )
        dkim_gateway = dkim_analysis.get('security_gateway')
        if dkim_strong and dkim_has_inferred:
            dkim_note = f' DKIM keys verified with strong cryptography. {dkim_analysis.get("primary_dkim_note", "")}'
        elif dkim_strong and dkim_gateway:
            dkim_note = f' DKIM keys verified with strong cryptography (signed by {dkim_primary_provider} via {dkim_gateway} gateway).'
        elif dkim_strong:
            dkim_note = ' DKIM keys verified with strong cryptography.'
        elif dkim_third_party_only:
            found_provs = dkim_analysis.get('found_providers', [])
            third_party_names = ', '.join(found_provs) if found_provs else 'third-party services'
            dkim_note = f' Note: DKIM found for {third_party_names} only \u2014 primary mail platform ({dkim_primary_provider}) DKIM not verified.'
        else:
            dkim_note = ''
        
        is_no_mail = results.get('is_no_mail_domain', False)
        has_null_mx = results.get('has_null_mx', False)
        
        if is_no_mail and dmarc_reject:
            null_mx_note = ' Null MX (RFC 7505) confirms no inbound mail.' if has_null_mx else ''
            verdicts['email'] = f'Non-mail domain with full anti-spoofing protection. SPF -all rejects all senders, DMARC reject blocks spoofed messages.{null_mx_note}'
            verdicts['email_answer'] = 'No'
        elif spf_ok and dmarc_ok and dmarc_reject:
            verdicts['email'] = f'DMARC policy is reject - spoofed messages will be blocked by receiving servers.{dkim_note}'
            verdicts['email_answer'] = 'No'
        elif spf_ok and dmarc_ok and dmarc_quarantine:
            verdicts['email'] = f'DMARC policy is quarantine - spoofed messages will be flagged as spam.{dkim_note}'
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
        dnssec_inherited = results.get('dnssec_analysis', {}).get('chain_of_trust') == 'inherited'
        ns_ok = results.get('ns_delegation_analysis', {}).get('delegation_ok', False)
        
        if dnssec_ok and ns_ok:
            if dnssec_inherited:
                verdicts['domain'] = 'DNS responses are authenticated via parent zone DNSSEC. Subdomain within a signed zone.'
            else:
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
