import sys
import re
import os
import subprocess
import shutil
import logging
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        records = {t: [] for t in record_types}
        
        def query_type(rtype):
            return (rtype, self.dns_query(rtype, domain))
        
        with ThreadPoolExecutor(max_workers=6) as executor:
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
            status = 'warning'
            message = 'No DKIM records found for common selectors'
        
        return {
            'status': status,
            'message': message,
            'selectors': found_selectors
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
        """Return RDAP JSON data for domain - tries ALL sources with robust retries."""
        tld = self._get_tld(domain)
        logging.info(f"[RDAP] Looking up domain {domain}, TLD: {tld}")
        
        # Create robust session with automatic retries
        session = create_robust_session()
        
        headers = {
            'Accept': 'application/rdap+json',
            'User-Agent': 'Mozilla/5.0 (compatible; DNS-Analyzer/1.0)'
        }
        
        # Build list of ALL RDAP endpoints to try
        hardcoded_endpoints = {
            'com': ['https://rdap.verisign.com/com/v1/'],
            'net': ['https://rdap.verisign.com/net/v1/'],
            'org': ['https://rdap.publicinterestregistry.net/rdap/'],
            'io': ['https://rdap.nic.io/'],
            'tech': ['https://rdap.centralnic.com/tech/'],
            'dev': ['https://rdap.nic.google/'],
            'app': ['https://rdap.nic.google/'],
            'co': ['https://rdap.nic.co/'],
            'info': ['https://rdap.afilias.net/rdap/info/'],
            'biz': ['https://rdap.nic.biz/'],
            'me': ['https://rdap.nic.me/'],
            'uk': ['https://rdap.nominet.uk/uk/'],
            'de': ['https://rdap.denic.de/'],
        }
        
        # Collect all possible endpoints - TLD-specific FIRST for reliability
        all_endpoints = []
        if tld in hardcoded_endpoints:
            all_endpoints.extend(hardcoded_endpoints[tld])
        all_endpoints.append('https://rdap.org/')  # Universal fallback
        if tld in self.iana_rdap_map:
            for ep in self.iana_rdap_map[tld]:
                if ep not in all_endpoints:
                    all_endpoints.append(ep)
        
        logging.info(f"[RDAP] Will try {len(all_endpoints)} endpoints sequentially with retries")
        
        # Try endpoints SEQUENTIALLY (more reliable than parallel in restricted environments)
        for endpoint in all_endpoints:
            url = f"{endpoint.rstrip('/')}/domain/{domain}"
            try:
                logging.info(f"[RDAP] Trying: {url}")
                resp = session.get(url, timeout=20, headers=headers, allow_redirects=True)
                logging.info(f"[RDAP] Response {resp.status_code} from {endpoint}")
                if resp.status_code < 400:
                    data = resp.json()
                    if "errorCode" not in data and (data.get("ldhName") or data.get("objectClassName") == "domain"):
                        logging.info(f"[RDAP] SUCCESS from {endpoint}")
                        session.close()
                        return data
            except Exception as e:
                logging.warning(f"[RDAP] Error from {endpoint}: {type(e).__name__}: {e}")
        
        session.close()
        logging.warning(f"[RDAP] All {len(all_endpoints)} endpoints failed for {domain}")
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
        """Identify hosting and DNS providers."""
        hosting = "Unknown"
        dns_hosting = "Standard"
        
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
            # For simplicity in fast mode, we use the first IP
            ip = a_records[0]
            # Common Cloudflare IPs
            if ip.startswith(('104.16.', '104.17.', '104.18.', '172.64.', '172.67.', '108.162.', '190.93.', '197.234.', '198.41.')):
                hosting = "Cloudflare"
            elif ip.startswith(('34.', '35.', '104.196.')):
                hosting = "Google Cloud"
            elif ip.startswith(('3.', '13.', '15.', '18.', '52.', '54.')):
                hosting = "AWS / Amazon"
            elif dns_hosting != "Standard":
                hosting = dns_hosting # Often the same
        
        return {
            'hosting': hosting,
            'dns_hosting': dns_hosting
        }

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Perform complete DNS analysis of domain with parallel lookups for speed."""
        
        # Run all lookups in parallel for speed (5-10s target)
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                executor.submit(self.get_basic_records, domain): 'basic',
                executor.submit(self.get_authoritative_records, domain): 'auth',
                executor.submit(self.analyze_spf, domain): 'spf',
                executor.submit(self.analyze_dmarc, domain): 'dmarc',
                executor.submit(self.analyze_dkim, domain): 'dkim',
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
            'registrar_info': results_map.get('registrar', {'status': 'error', 'registrar': None})
        }
        
        # Add Hosting/Who summary
        results['hosting_summary'] = self.get_hosting_info(domain, results)
        
        return results
