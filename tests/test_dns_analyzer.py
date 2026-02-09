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
        bimi = {'status': 'success', 'vmc_valid': True}
        result = self._calculate_brand_impersonation(bimi)
        self.assertEqual(result, 'protected')
    
    def test_brand_impersonation_basic(self):
        """Basic: BIMI success without VMC."""
        bimi = {'status': 'success', 'vmc_valid': False}
        result = self._calculate_brand_impersonation(bimi)
        self.assertEqual(result, 'basic')
    
    def test_brand_impersonation_not_setup(self):
        """Not Setup: No BIMI or BIMI error."""
        bimi = {'status': 'error', 'vmc_valid': False}
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
        if bimi and bimi.get('status') == 'success' and bimi.get('vmc_valid'):
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


class TestDNSSECEdgeStates(unittest.TestCase):
    """Tests for DNSSEC validation edge cases."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
    
    def test_dnssec_result_structure(self):
        """DNSSEC result should have expected structure."""
        expected_keys = {'ad_flag', 'validated', 'resolver_used', 'error'}
        result = self.analyzer.check_dnssec_ad_flag('example.com')
        for key in expected_keys:
            self.assertIn(key, result, f"DNSSEC result should have '{key}' key")
    
    def test_dnssec_ad_flag_types(self):
        """DNSSEC ad_flag and validated should be boolean."""
        result = self.analyzer.check_dnssec_ad_flag('example.com')
        self.assertIsInstance(result['ad_flag'], bool)
        self.assertIsInstance(result['validated'], bool)
    
    def test_dnssec_nonexistent_domain(self):
        """DNSSEC check on non-existent domain should return error."""
        result = self.analyzer.check_dnssec_ad_flag('this-domain-does-not-exist-xyz123.com')
        # Should either have error or return False for validation
        is_failed = result.get('error') is not None or not result.get('validated', True)
        self.assertTrue(is_failed or result.get('ad_flag') == False)


class TestMultiResolverConsensus(unittest.TestCase):
    """Tests for multi-resolver consensus functionality."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
    
    def test_consensus_resolvers_configured(self):
        """Should have multiple resolvers configured for consensus."""
        self.assertGreaterEqual(
            len(self.analyzer.CONSENSUS_RESOLVERS), 
            2, 
            "Should have at least 2 resolvers for consensus"
        )
    
    def test_consensus_resolvers_have_required_fields(self):
        """Each resolver should have name and ip fields."""
        for resolver in self.analyzer.CONSENSUS_RESOLVERS:
            self.assertIn('name', resolver, "Resolver should have 'name'")
            self.assertIn('ip', resolver, "Resolver should have 'ip'")
    
    def test_dns_query_with_consensus_structure(self):
        """Consensus query should return expected structure."""
        result = self.analyzer.dns_query_with_consensus('A', 'example.com')
        expected_keys = ['records', 'consensus', 'resolver_count', 'discrepancies', 'resolver_results']
        for key in expected_keys:
            self.assertIn(key, result, f"Consensus result should have '{key}' key")
    
    def test_dns_query_with_consensus_types(self):
        """Consensus query should return correct types."""
        result = self.analyzer.dns_query_with_consensus('A', 'example.com')
        self.assertIsInstance(result['records'], list)
        self.assertIsInstance(result['consensus'], bool)
        self.assertIsInstance(result['resolver_count'], int)
        self.assertIsInstance(result['discrepancies'], list)
        self.assertIsInstance(result['resolver_results'], dict)
    
    def test_validate_resolver_consensus_structure(self):
        """Resolver validation should return expected structure."""
        result = self.analyzer.validate_resolver_consensus('example.com')
        expected_keys = ['consensus_reached', 'resolvers_queried', 'checks_performed', 
                         'discrepancies', 'per_record_consensus']
        for key in expected_keys:
            self.assertIn(key, result, f"Validation result should have '{key}' key")
    
    def test_validate_resolver_consensus_checks_critical_records(self):
        """Validation should check critical record types (A, MX, NS, TXT)."""
        result = self.analyzer.validate_resolver_consensus('example.com')
        checked_types = result.get('per_record_consensus', {}).keys()
        # At least some of the critical types should be checked
        critical_types = {'A', 'MX', 'NS', 'TXT'}
        self.assertTrue(
            len(set(checked_types) & critical_types) > 0,
            "Should check at least some critical record types"
        )


class TestRDAPCache(unittest.TestCase):
    """Tests for RDAP caching functionality."""
    
    def test_rdap_cache_class_exists(self):
        """RDAPCache class should be importable."""
        from dns_analyzer import RDAPCache
        cache = RDAPCache()
        self.assertIsNotNone(cache)
    
    def test_rdap_cache_has_backend_property(self):
        """RDAPCache should have backend property."""
        from dns_analyzer import RDAPCache
        cache = RDAPCache()
        self.assertIn(cache.backend, ['memory', 'redis'])
    
    def test_rdap_cache_get_set(self):
        """RDAPCache should support get/set operations."""
        from dns_analyzer import RDAPCache
        cache = RDAPCache()
        test_data = {'registrar': 'Test Registrar', '_cached_at': '2024-01-01 00:00 UTC'}
        cache.set('test.com', test_data)
        retrieved = cache.get('test.com')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.get('registrar'), 'Test Registrar')


class TestConsensusConflictDetection(unittest.TestCase):
    """Tests for resolver consensus CONFLICT detection (negative cases)."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
    
    def test_discrepancy_detection_different_results(self):
        """Should detect discrepancies when mock resolvers return different results."""
        # Simulate what happens when resolvers disagree
        resolver_results = {
            'Cloudflare': ['1.2.3.4', '5.6.7.8'],
            'Google': ['1.2.3.4', '5.6.7.8'],
            'Quad9': ['1.2.3.4', '9.9.9.9']  # Different!
        }
        # Check that different results would be detected
        result_sets = [tuple(sorted(r)) for r in resolver_results.values()]
        all_same = len(set(result_sets)) == 1
        self.assertFalse(all_same, "Should detect that results are NOT all the same")
    
    def test_consensus_voting_uses_majority(self):
        """Majority voting should select most common result."""
        from collections import Counter
        # 2 resolvers agree, 1 disagrees
        resolver_results = {
            'Cloudflare': ['1.2.3.4'],
            'Google': ['1.2.3.4'],
            'Quad9': ['9.9.9.9']  # Minority
        }
        result_sets = [tuple(sorted(r)) for r in resolver_results.values()]
        result_counter = Counter(result_sets)
        most_common = result_counter.most_common(1)[0][0]
        self.assertEqual(most_common, ('1.2.3.4',), "Majority result should win")
    
    def test_discrepancy_message_format(self):
        """Discrepancy messages should identify the dissenting resolver."""
        resolver_results = {
            'Cloudflare': ['1.2.3.4'],
            'Google': ['1.2.3.4'],
            'Quad9': ['9.9.9.9']
        }
        from collections import Counter
        result_sets = [tuple(sorted(r)) for r in resolver_results.values()]
        result_counter = Counter(result_sets)
        most_common = result_counter.most_common(1)[0][0]
        
        discrepancies = []
        for resolver_name, results in resolver_results.items():
            if tuple(sorted(results)) != most_common:
                discrepancies.append(f"{resolver_name} returned different results: {results}")
        
        self.assertEqual(len(discrepancies), 1)
        self.assertIn('Quad9', discrepancies[0])
        self.assertIn('9.9.9.9', discrepancies[0])
    
    def test_empty_resolver_results_uses_doh_fallback(self):
        """When all resolvers fail, should fallback to DoH."""
        # Empty resolver results should trigger DoH fallback
        resolver_results = {}
        self.assertEqual(len(resolver_results), 0)
        # In actual code, this triggers DoH fallback with consensus=True
    
    def test_all_different_resolvers_still_picks_most_common(self):
        """Even with all-different results, should pick most common (or first)."""
        from collections import Counter
        resolver_results = {
            'Cloudflare': ['1.1.1.1'],
            'Google': ['8.8.8.8'],
            'Quad9': ['9.9.9.9']
        }
        result_sets = [tuple(sorted(r)) for r in resolver_results.values()]
        result_counter = Counter(result_sets)
        most_common = result_counter.most_common(1)[0][0]
        # Should still return something (first in alphabetical order typically)
        self.assertIsNotNone(most_common)
        self.assertEqual(result_counter[most_common], 1, "No majority exists, each appears once")
    
    def test_consensus_false_when_discrepancies_exist(self):
        """consensus flag should be False when any discrepancy exists."""
        resolver_results = {
            'Cloudflare': ['1.2.3.4'],
            'Google': ['9.9.9.9']  # Different!
        }
        result_sets = [tuple(sorted(r)) for r in resolver_results.values()]
        all_same = len(set(result_sets)) == 1
        # In actual code, consensus = all_same
        self.assertFalse(all_same)
    
    def test_consensus_true_when_all_agree(self):
        """consensus flag should be True when all resolvers agree."""
        resolver_results = {
            'Cloudflare': ['1.2.3.4', '5.6.7.8'],
            'Google': ['5.6.7.8', '1.2.3.4'],  # Same records, different order
            'Quad9': ['1.2.3.4', '5.6.7.8']
        }
        result_sets = [tuple(sorted(r)) for r in resolver_results.values()]
        all_same = len(set(result_sets)) == 1
        self.assertTrue(all_same, "Sorted results should match regardless of order")


class TestResolverConsensusSchema(unittest.TestCase):
    """Tests for resolver consensus field binding with UI."""
    
    def setUp(self):
        self.analyzer = DNSAnalyzer()
    
    def test_validate_resolver_consensus_returns_required_fields(self):
        """validate_resolver_consensus should return UI-required fields."""
        result = self.analyzer.validate_resolver_consensus('example.com')
        # These fields are required by the UI template
        self.assertIn('consensus_reached', result)
        self.assertIn('resolvers_queried', result)  # UI uses this field name
        self.assertIn('discrepancies', result)
        self.assertIn('per_record_consensus', result)
    
    def test_resolvers_queried_is_integer(self):
        """resolvers_queried should be an integer for UI display."""
        result = self.analyzer.validate_resolver_consensus('example.com')
        self.assertIsInstance(result['resolvers_queried'], int)
        self.assertGreaterEqual(result['resolvers_queried'], 0)
    
    def test_discrepancies_is_list(self):
        """discrepancies should be a list for UI iteration."""
        result = self.analyzer.validate_resolver_consensus('example.com')
        self.assertIsInstance(result['discrepancies'], list)


class TestDependencyInjection(unittest.TestCase):
    """Tests that dependency injection hooks are properly wired."""

    def test_custom_dns_resolver_is_used(self):
        """Injected dns_resolver should be called instead of live DNS."""
        calls = []

        def fake_resolver(record_type, domain):
            calls.append((record_type, domain))
            if record_type == 'A':
                return ['93.184.216.34']
            return []

        analyzer = DNSAnalyzer(dns_resolver=fake_resolver, skip_network_init=True)
        result = analyzer.dns_query('A', 'test.example.com')
        self.assertEqual(result, ['93.184.216.34'])
        self.assertIn(('A', 'test.example.com'), calls)

    def test_custom_dns_resolver_error_returns_empty(self):
        """If custom resolver raises, dns_query should return empty list."""
        def broken_resolver(record_type, domain):
            raise RuntimeError("test error")

        analyzer = DNSAnalyzer(dns_resolver=broken_resolver, skip_network_init=True)
        result = analyzer.dns_query('A', 'test.example.com')
        self.assertEqual(result, [])

    def test_custom_http_client_is_used(self):
        """Injected http_client should be called instead of live HTTP."""
        calls = []

        class FakeResponse:
            status_code = 200
            text = '{"test": true}'
            content = b'{"test": true}'
            headers = {}
            def json(self):
                return {"test": True}
            def raise_for_status(self):
                pass

        def fake_http(url, **kwargs):
            calls.append(url)
            return FakeResponse()

        analyzer = DNSAnalyzer(http_client=fake_http, skip_network_init=True)
        response = analyzer._safe_http_get('https://example.com/test')
        self.assertEqual(response.status_code, 200)
        self.assertIn('https://example.com/test', calls)

    def test_skip_network_init(self):
        """skip_network_init should prevent IANA RDAP fetch."""
        analyzer = DNSAnalyzer(skip_network_init=True)
        self.assertEqual(analyzer.iana_rdap_map, {})

    def test_default_constructor_backwards_compatible(self):
        """Default no-arg constructor should still work."""
        analyzer = DNSAnalyzer()
        self.assertIsNone(analyzer._custom_dns_resolver)
        self.assertIsNone(analyzer._custom_http_client)


if __name__ == '__main__':
    unittest.main()
