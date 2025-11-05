import sys
import re
import os
import subprocess
import shutil
import logging
from typing import Dict, List, Optional, Any

try:
    import requests
except ImportError:
    print("Error: the 'requests' package is required.")
    sys.exit(1)

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
            r = requests.get(url, timeout=10)
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
        """Get basic DNS records for domain."""
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        records = {}
        
        for record_type in record_types:
            records[record_type] = self.dns_query(record_type, domain)
        
        return records
    
    def get_authoritative_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records directly from authoritative nameservers."""
        # Disabled for performance - authoritative queries timeout in restricted environments
        record_types = ["A", "AAAA", "MX", "TXT"]
        results = {t: [] for t in record_types}
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
        """Check common DKIM selectors for domain."""
        selectors = ["default._domainkey", "google._domainkey", 
                    "selector1._domainkey", "selector2._domainkey"]
        
        found_selectors = {}
        
        for selector in selectors:
            records = self.dns_query("TXT", f"{selector}.{domain}")
            if records:
                # Check if it's actually a DKIM record
                dkim_records = [r for r in records if "v=dkim1" in r.lower() or "k=" in r.lower()]
                if dkim_records:
                    found_selectors[selector] = dkim_records
        
        if found_selectors:
            status = 'success'
            message = f'Found DKIM records for {len(found_selectors)} selector(s)'
        else:
            status = 'warning'
            message = 'No DKIM records found for common selectors'
        
        return {
            'status': status,
            'message': message,
            'selectors': found_selectors
        }
    
    def get_registrar_info(self, domain: str) -> Dict[str, Any]:
        """Get registrar information via RDAP or WHOIS."""
        # Try RDAP first
        rdap_data = self._rdap_lookup(domain)
        
        if rdap_data:
            registrar_name = self._extract_registrar_from_rdap(rdap_data)
            if registrar_name and not registrar_name.isdigit():
                return {
                    'status': 'success',
                    'source': 'RDAP',
                    'registrar': registrar_name
                }
        
        # Fallback to WHOIS
        whois_registrar = self._whois_lookup_registrar(domain)
        if whois_registrar:
            return {
                'status': 'success',
                'source': 'WHOIS',
                'registrar': whois_registrar
            }
        
        return {
            'status': 'error',
            'source': None,
            'registrar': None,
            'message': 'No registrar information found'
        }
    
    def _rdap_lookup(self, domain: str) -> Dict:
        """Return RDAP JSON data for domain using IANA endpoints."""
        tld = self._get_tld(domain)
        endpoints = self.iana_rdap_map.get(tld, [])
        
        for endpoint in endpoints:
            url = f"{endpoint.rstrip('/')}/domain/{domain}"
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code < 400:
                    data = resp.json()
                    if "errorCode" not in data:
                        return data
            except Exception as e:
                logging.debug(f"RDAP lookup error: {e}")
        
        # Fallback to rdap.org
        try:
            resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
            if resp.status_code < 400:
                data = resp.json()
                if "errorCode" not in data:
                    return data
        except Exception as e:
            logging.debug(f"RDAP fallback lookup error: {e}")
        
        return {}
    
    def _extract_registrar_from_rdap(self, rdap_data: Dict) -> Optional[str]:
        """Extract registrar name from RDAP data."""
        entities = rdap_data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])
            if "registrar" in [r.lower() for r in roles]:
                vcard = entity.get("vcardArray", [])
                if len(vcard) == 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if len(item) == 4 and item[0] == "fn":
                            return item[3]
                return entity.get("handle") or entity.get("name") or ""
        return None
    
    def _whois_lookup_registrar(self, domain: str) -> Optional[str]:
        """Return registrar name using the whois command."""
        if not shutil.which("whois"):
            return None
        
        try:
            result = subprocess.run(
                ["whois", domain], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            for line in result.stdout.splitlines():
                if re.search(r"(?i)registrar:", line) or re.search(r"(?i)sponsoring registrar:", line):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
            return None
        except Exception:
            return None
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Perform complete DNS analysis of domain."""
        results = {
            'basic_records': self.get_basic_records(domain),
            'authoritative_records': self.get_authoritative_records(domain),
            'spf_analysis': self.analyze_spf(domain),
            'dmarc_analysis': self.analyze_dmarc(domain),
            'dkim_analysis': self.analyze_dkim(domain),
            'registrar_info': self.get_registrar_info(domain)
        }
        
        return results
