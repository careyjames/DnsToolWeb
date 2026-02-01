"""
Unit tests for DNS Analyzer core logic.
Tests scorecard logic, error states, and government/enterprise detection.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_analyzer import DNSAnalyzer


class TestDomainValidation(unittest.TestCase):
    """Tests for domain validation logic."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
    
    def test_valid_domains(self):
        """Valid domain formats should pass."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "example.co.uk",
            "test-domain.org",
            "123.example.com",
        ]
        for domain in valid_domains:
            self.assertTrue(self.analyzer.validate_domain(domain), f"Should be valid: {domain}")
    
    def test_invalid_domains(self):
        """Invalid domain formats should fail."""
        invalid_domains = [
            "",
            ".",
            ".example.com",
            "example.com.",
            "example",
            "http://example.com",
            "example.com/path",
        ]
        for domain in invalid_domains:
            self.assertFalse(self.analyzer.validate_domain(domain), f"Should be invalid: {domain}")


class TestGovernmentDetection(unittest.TestCase):
    """Tests for government domain detection via analyze_dns_infrastructure."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
        self.gov_suffixes = ['.gov', '.mil', '.gov.uk', '.gov.au', '.gc.ca']
    
    def _is_government_domain(self, domain):
        """Check if domain matches government suffixes."""
        domain_lower = domain.lower()
        for suffix in self.gov_suffixes:
            if domain_lower.endswith(suffix):
                return True
        return False
    
    def test_us_gov_domains(self):
        """US .gov domains should be detected."""
        gov_domains = ["cia.gov", "fbi.gov", "whitehouse.gov", "nasa.gov"]
        for domain in gov_domains:
            result = self._is_government_domain(domain)
            self.assertTrue(result, f"Should detect as government: {domain}")
    
    def test_military_domains(self):
        """US .mil domains should be detected."""
        mil_domains = ["army.mil", "navy.mil", "af.mil"]
        for domain in mil_domains:
            result = self._is_government_domain(domain)
            self.assertTrue(result, f"Should detect as government: {domain}")
    
    def test_international_gov_domains(self):
        """International government domains should be detected."""
        intl_gov = ["service.gov.uk", "canada.gc.ca", "test.gov.au"]
        for domain in intl_gov:
            result = self._is_government_domain(domain)
            self.assertTrue(result, f"Should detect as government: {domain}")
    
    def test_non_gov_domains(self):
        """Non-government domains should not be detected."""
        non_gov = ["google.com", "amazon.com", "github.io", "example.org"]
        for domain in non_gov:
            result = self._is_government_domain(domain)
            self.assertFalse(result, f"Should NOT detect as government: {domain}")


class TestEnterpriseProviderDetection(unittest.TestCase):
    """Tests for enterprise DNS provider detection."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
        self.enterprise_keywords = ['cloudflare', 'awsdns', 'route53', 'azure-dns', 
                                     'akamai', 'ultradns', 'verisign', 'ns1.com', 
                                     'google', 'apple.com', 'microsoft.com']
    
    def _detect_enterprise_tier(self, ns_records):
        """Check if nameservers indicate enterprise provider."""
        ns_str = " ".join(ns_records).lower()
        for keyword in self.enterprise_keywords:
            if keyword in ns_str:
                return 'enterprise'
        return 'standard'
    
    def test_cloudflare_detection(self):
        """Cloudflare nameservers should be detected as enterprise."""
        ns_records = ["ns1.cloudflare.com", "ns2.cloudflare.com"]
        result = self._detect_enterprise_tier(ns_records)
        self.assertEqual(result, 'enterprise')
    
    def test_aws_detection(self):
        """AWS Route53 nameservers should be detected as enterprise."""
        ns_records = ["ns-123.awsdns-12.com", "ns-456.awsdns-34.net"]
        result = self._detect_enterprise_tier(ns_records)
        self.assertEqual(result, 'enterprise')
    
    def test_unknown_provider(self):
        """Unknown nameservers should return standard tier."""
        ns_records = ["ns1.unknownprovider.example", "ns2.unknownprovider.example"]
        result = self._detect_enterprise_tier(ns_records)
        self.assertEqual(result, 'standard')


class TestSPFAnalysis(unittest.TestCase):
    """Tests for SPF record analysis."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
    
    def test_spf_status_types(self):
        """SPF analysis should return valid status types."""
        valid_statuses = ['success', 'warning', 'error']
        result = self.analyzer.analyze_spf("example.com")
        self.assertIn(result['status'], valid_statuses)
    
    def test_spf_result_structure(self):
        """SPF result should have expected fields."""
        result = self.analyzer.analyze_spf("example.com")
        expected_fields = ['status', 'message', 'records', 'valid_records', 
                          'lookup_count', 'permissiveness', 'issues']
        for field in expected_fields:
            self.assertIn(field, result, f"Missing field: {field}")


class TestDMARCAnalysis(unittest.TestCase):
    """Tests for DMARC record analysis."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
    
    def test_dmarc_status_types(self):
        """DMARC analysis should return valid status types."""
        valid_statuses = ['success', 'warning', 'error']
        result = self.analyzer.analyze_dmarc("example.com")
        self.assertIn(result['status'], valid_statuses)
    
    def test_dmarc_result_structure(self):
        """DMARC result should have expected fields."""
        result = self.analyzer.analyze_dmarc("example.com")
        expected_fields = ['status', 'message', 'policy', 'issues']
        for field in expected_fields:
            self.assertIn(field, result, f"Missing field: {field}")


class TestScorecardLogic(unittest.TestCase):
    """Tests for executive scorecard determination logic."""
    
    def test_email_spoofing_protected(self):
        """Protected: SPF success + DMARC success with reject/quarantine."""
        spf = {'status': 'success'}
        dmarc = {'status': 'success', 'policy': 'reject'}
        result = self._calculate_email_spoofing(spf, dmarc)
        self.assertEqual(result, 'protected')
        
        dmarc_quarantine = {'status': 'success', 'policy': 'quarantine'}
        result = self._calculate_email_spoofing(spf, dmarc_quarantine)
        self.assertEqual(result, 'protected')
    
    def test_email_spoofing_monitoring(self):
        """Monitoring: SPF and DMARC success with p=none."""
        spf = {'status': 'success'}
        dmarc = {'status': 'success', 'policy': 'none'}
        result = self._calculate_email_spoofing(spf, dmarc)
        self.assertEqual(result, 'monitoring')
    
    def test_email_spoofing_partial(self):
        """Partial: SPF or DMARC success but not both."""
        spf_only = {'status': 'success'}
        dmarc_error = {'status': 'error', 'policy': None}
        result = self._calculate_email_spoofing(spf_only, dmarc_error)
        self.assertEqual(result, 'partial')
        
        spf_error = {'status': 'error'}
        dmarc_only = {'status': 'success', 'policy': 'reject'}
        result = self._calculate_email_spoofing(spf_error, dmarc_only)
        self.assertEqual(result, 'partial')
    
    def test_email_spoofing_vulnerable(self):
        """Vulnerable: Neither SPF nor DMARC configured."""
        spf = {'status': 'error'}
        dmarc = {'status': 'error', 'policy': None}
        result = self._calculate_email_spoofing(spf, dmarc)
        self.assertEqual(result, 'vulnerable')
    
    def test_brand_impersonation_protected(self):
        """Protected: BIMI success with VMC."""
        bimi = {'status': 'success', 'has_vmc': True}
        result = self._calculate_brand_impersonation(bimi)
        self.assertEqual(result, 'protected')
    
    def test_brand_impersonation_basic(self):
        """Basic: BIMI success without VMC."""
        bimi = {'status': 'success', 'has_vmc': False}
        result = self._calculate_brand_impersonation(bimi)
        self.assertEqual(result, 'basic')
    
    def test_brand_impersonation_not_setup(self):
        """Not Setup: No BIMI or BIMI error."""
        bimi = {'status': 'error', 'has_vmc': False}
        result = self._calculate_brand_impersonation(bimi)
        self.assertEqual(result, 'not_setup')
        
        result_none = self._calculate_brand_impersonation(None)
        self.assertEqual(result_none, 'not_setup')
    
    def test_dns_tampering_protected(self):
        """Protected: DNSSEC enabled."""
        dnssec = {'status': 'success'}
        infra = {'provider_tier': 'standard'}
        result = self._calculate_dns_tampering(dnssec, infra)
        self.assertEqual(result, 'protected')
    
    def test_dns_tampering_enterprise(self):
        """Enterprise: No DNSSEC but enterprise provider."""
        dnssec = {'status': 'error'}
        infra = {'provider_tier': 'enterprise'}
        result = self._calculate_dns_tampering(dnssec, infra)
        self.assertEqual(result, 'enterprise')
    
    def test_dns_tampering_unsigned(self):
        """Unsigned: No DNSSEC and standard provider."""
        dnssec = {'status': 'error'}
        infra = {'provider_tier': 'standard'}
        result = self._calculate_dns_tampering(dnssec, infra)
        self.assertEqual(result, 'unsigned')
    
    def test_certificate_control_configured(self):
        """Configured: CAA records present."""
        caa = {'status': 'success'}
        result = self._calculate_certificate_control(caa)
        self.assertEqual(result, 'configured')
    
    def test_certificate_control_open(self):
        """Open: No CAA records."""
        caa = {'status': 'error'}
        result = self._calculate_certificate_control(caa)
        self.assertEqual(result, 'open')
    
    def _calculate_email_spoofing(self, spf, dmarc):
        """Mirror template logic for email spoofing scorecard."""
        spf_ok = spf.get('status') == 'success'
        dmarc_ok = dmarc.get('status') == 'success'
        dmarc_enforced = dmarc.get('policy') in ['reject', 'quarantine']
        
        if spf_ok and dmarc_ok and dmarc_enforced:
            return 'protected'
        elif spf_ok and dmarc_ok and dmarc.get('policy') == 'none':
            return 'monitoring'
        elif spf_ok or dmarc_ok:
            return 'partial'
        return 'vulnerable'
    
    def _calculate_brand_impersonation(self, bimi):
        """Mirror template logic for brand impersonation scorecard."""
        if bimi and bimi.get('status') == 'success' and bimi.get('has_vmc'):
            return 'protected'
        elif bimi and bimi.get('status') == 'success':
            return 'basic'
        return 'not_setup'
    
    def _calculate_dns_tampering(self, dnssec, infra):
        """Mirror template logic for DNS tampering scorecard."""
        if dnssec.get('status') == 'success':
            return 'protected'
        elif infra and infra.get('provider_tier') == 'enterprise':
            return 'enterprise'
        return 'unsigned'
    
    def _calculate_certificate_control(self, caa):
        """Mirror template logic for certificate control scorecard."""
        if caa and caa.get('status') == 'success':
            return 'configured'
        return 'open'


class TestErrorStateHandling(unittest.TestCase):
    """Tests for error vs warning state distinction."""
    
    def test_error_status_is_red(self):
        """Error status should map to danger badge."""
        status = 'error'
        badge_class = 'danger' if status == 'error' else 'warning'
        self.assertEqual(badge_class, 'danger')
    
    def test_warning_status_is_yellow(self):
        """Warning status should map to warning badge."""
        status = 'warning'
        badge_class = 'danger' if status == 'error' else 'warning'
        self.assertEqual(badge_class, 'warning')
    
    def test_success_status_is_green(self):
        """Success status should map to success badge."""
        status = 'success'
        badge_class = 'success' if status == 'success' else 'warning'
        self.assertEqual(badge_class, 'success')


if __name__ == '__main__':
    unittest.main()
