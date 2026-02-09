"""
Edge-case contract tests for DNS Analyzer.
Uses dependency injection to test deterministic scenarios
that protect analysis logic during Go migration.
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.analyzer_interface import create_test_analyzer
from tests.schema_contract import validate_analysis_results, VALID_STATUS_VALUES


def make_dns_resolver(records_map):
    def resolver(record_type, domain):
        key = (record_type.upper(), domain.lower().rstrip('.'))
        value = records_map.get(key)
        if value is None:
            return []
        if isinstance(value, Exception):
            raise value
        return value
    return resolver


def make_http_client(responses_map):
    class MockResponse:
        def __init__(self, status_code=200, text='', json_data=None, headers=None):
            self.status_code = status_code
            self.text = text
            self._json = json_data
            self.headers = headers or {}
            self.ok = 200 <= status_code < 300
            self.content = text.encode('utf-8') if isinstance(text, str) else text
        def json(self):
            if self._json is not None:
                return self._json
            import json
            return json.loads(self.text)
        def raise_for_status(self):
            if not self.ok:
                raise Exception(f'HTTP {self.status_code}')

    def client(url, **kwargs):
        for prefix, response in responses_map.items():
            if url.startswith(prefix):
                if isinstance(response, Exception):
                    raise response
                return response
        return MockResponse(status_code=404, text='Not found')
    return client


class TestNonExistentDomain(unittest.TestCase):

    def setUp(self):
        self.analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({}),
            http_client=make_http_client({}),
        )

    def test_nonexistent_domain_exists_false(self):
        result = self.analyzer.analyze_domain('nxdomain-test-xyz.com')
        self.assertFalse(result.get('domain_exists'))

    def test_nonexistent_domain_status(self):
        result = self.analyzer.analyze_domain('nxdomain-test-xyz.com')
        self.assertEqual(result.get('domain_status'), 'undelegated')
        self.assertIsNotNone(result.get('domain_status_message'))

    def test_nonexistent_domain_all_sections_na(self):
        result = self.analyzer.analyze_domain('nxdomain-test-xyz.com')
        na_sections = [
            'spf_analysis', 'dmarc_analysis', 'dkim_analysis',
            'mta_sts_analysis', 'tlsrpt_analysis', 'bimi_analysis',
            'dane_analysis', 'caa_analysis', 'dnssec_analysis',
        ]
        for section in na_sections:
            section_data = result.get(section, {})
            self.assertEqual(
                section_data.get('status'), 'n/a',
                f'{section} should have status n/a, got {section_data.get("status")}'
            )

    def test_nonexistent_domain_posture_structure(self):
        result = self.analyzer.analyze_domain('nxdomain-test-xyz.com')
        posture = result.get('posture', {})
        self.assertIn('score', posture)
        self.assertIn('grade', posture)
        self.assertIn('label', posture)
        self.assertIn('issues', posture)
        self.assertIn('color', posture)
        self.assertEqual(posture['score'], 0)

    def test_nonexistent_domain_passes_schema(self):
        result = self.analyzer.analyze_domain('nxdomain-test-xyz.com')
        errors = validate_analysis_results(result)
        self.assertEqual(errors, [], f'Schema errors: {errors}')

    def test_nonexistent_domain_dane_structure(self):
        result = self.analyzer.analyze_domain('nxdomain-test-xyz.com')
        dane = result.get('dane_analysis', {})
        self.assertFalse(dane.get('has_dane'))
        self.assertEqual(dane.get('tlsa_records'), [])
        self.assertEqual(dane.get('issues'), [])


class TestTimeoutHandling(unittest.TestCase):

    def test_dns_timeout_returns_empty(self):
        import dns.resolver
        def timeout_resolver(record_type, domain):
            raise dns.resolver.Timeout()
        analyzer = create_test_analyzer(
            dns_resolver=timeout_resolver,
            http_client=make_http_client({}),
        )
        result = analyzer.dns_query('A', 'example.com')
        self.assertEqual(result, [])

    def test_dns_exception_returns_empty(self):
        def error_resolver(record_type, domain):
            raise ConnectionError("Network unreachable")
        analyzer = create_test_analyzer(
            dns_resolver=error_resolver,
            http_client=make_http_client({}),
        )
        result = analyzer.dns_query('A', 'example.com')
        self.assertEqual(result, [])


class TestActiveDomainWithMocks(unittest.TestCase):

    def setUp(self):
        self.dns_records = {
            ('A', 'example-active.com'): ['93.184.216.34'],
            ('AAAA', 'example-active.com'): ['2606:2800:220:1:248:1893:25c8:1946'],
            ('MX', 'example-active.com'): ['10 mail.example-active.com.'],
            ('NS', 'example-active.com'): ['ns1.example.com.', 'ns2.example.com.'],
            ('TXT', 'example-active.com'): ['v=spf1 include:_spf.google.com ~all'],
            ('TXT', '_dmarc.example-active.com'): ['v=DMARC1; p=reject; rua=mailto:dmarc@example-active.com'],
            ('SOA', 'example-active.com'): ['ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400'],
            ('CNAME', 'example-active.com'): [],
            ('CAA', 'example-active.com'): ['0 issue "letsencrypt.org"'],
        }
        self.analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver(self.dns_records),
            http_client=make_http_client({}),
        )

    def test_active_domain_exists_true(self):
        result = self.analyzer.analyze_domain('example-active.com')
        self.assertTrue(result.get('domain_exists'))

    def test_active_domain_has_all_sections(self):
        result = self.analyzer.analyze_domain('example-active.com')
        required_sections = [
            'basic_records', 'spf_analysis', 'dmarc_analysis',
            'dkim_analysis', 'registrar_info', 'posture',
            'dane_analysis', 'mta_sts_analysis', 'tlsrpt_analysis',
            'bimi_analysis', 'caa_analysis', 'dnssec_analysis',
        ]
        for section in required_sections:
            self.assertIn(section, result, f'Missing section: {section}')

    def test_active_domain_posture_has_graduated_fields(self):
        result = self.analyzer.analyze_domain('example-active.com')
        posture = result.get('posture', {})
        for field in ['state', 'message', 'issues', 'color', 'configured', 'absent', 'monitoring', 'verdicts']:
            self.assertIn(field, posture, f'Missing posture field: {field}')

    def test_active_domain_section_statuses_valid(self):
        result = self.analyzer.analyze_domain('example-active.com')
        status_sections = [
            'spf_analysis', 'dmarc_analysis', 'dkim_analysis',
            'dane_analysis', 'mta_sts_analysis', 'tlsrpt_analysis',
            'bimi_analysis', 'caa_analysis', 'dnssec_analysis',
        ]
        for section in status_sections:
            section_data = result.get(section, {})
            status = section_data.get('status')
            self.assertIn(status, VALID_STATUS_VALUES, f'{section} invalid status: {status}')

    def test_active_domain_passes_schema(self):
        result = self.analyzer.analyze_domain('example-active.com')
        errors = validate_analysis_results(result)
        self.assertEqual(errors, [], f'Schema errors: {errors}')

    def test_active_domain_basic_records_structure(self):
        result = self.analyzer.analyze_domain('example-active.com')
        basic = result.get('basic_records', {})
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            self.assertIn(rtype, basic, f'Missing record type: {rtype}')
            self.assertIsInstance(basic[rtype], list, f'{rtype} should be a list')

    def test_active_domain_hosting_summary(self):
        result = self.analyzer.analyze_domain('example-active.com')
        hs = result.get('hosting_summary', {})
        for field in ['hosting', 'dns_hosting', 'email_hosting']:
            self.assertIn(field, hs)
            self.assertIsInstance(hs[field], str)

    def test_active_domain_mail_posture(self):
        result = self.analyzer.analyze_domain('example-active.com')
        mp = result.get('mail_posture', {})
        self.assertIn('classification', mp)
        self.assertIsInstance(mp['classification'], str)


class TestNoMailDomain(unittest.TestCase):

    def setUp(self):
        self.dns_records = {
            ('A', 'nomail-test.com'): ['93.184.216.34'],
            ('MX', 'nomail-test.com'): ['0 .'],
            ('NS', 'nomail-test.com'): ['ns1.example.com.'],
            ('TXT', 'nomail-test.com'): ['v=spf1 -all'],
            ('TXT', '_dmarc.nomail-test.com'): ['v=DMARC1; p=reject;'],
            ('SOA', 'nomail-test.com'): ['ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400'],
            ('AAAA', 'nomail-test.com'): [],
            ('CNAME', 'nomail-test.com'): [],
            ('CAA', 'nomail-test.com'): [],
        }
        self.analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver(self.dns_records),
            http_client=make_http_client({}),
        )

    def test_no_mail_detected(self):
        result = self.analyzer.analyze_domain('nomail-test.com')
        self.assertTrue(result.get('has_null_mx') or result.get('is_no_mail_domain'))

    def test_no_mail_classification(self):
        result = self.analyzer.analyze_domain('nomail-test.com')
        mp = result.get('mail_posture', {})
        self.assertIn(mp.get('classification'), [
            'no_mail_verified', 'no_mail_partial', 'no_mail_intent',
            'email_enabled', 'email_minimal',
        ])

    def test_no_mail_passes_schema(self):
        result = self.analyzer.analyze_domain('nomail-test.com')
        errors = validate_analysis_results(result)
        self.assertEqual(errors, [], f'Schema errors: {errors}')


class TestIDNDomainHandling(unittest.TestCase):

    def setUp(self):
        self.analyzer = create_test_analyzer()

    def test_ascii_domain_unchanged(self):
        result = self.analyzer.domain_to_ascii('example.com')
        self.assertEqual(result, 'example.com')

    def test_unicode_domain_encoded(self):
        result = self.analyzer.domain_to_ascii('münchen.de')
        self.assertEqual(result, 'xn--mnchen-3ya.de')

    def test_trailing_dot_stripped(self):
        result = self.analyzer.domain_to_ascii('example.com.')
        self.assertEqual(result, 'example.com')

    def test_invalid_domain_raises(self):
        with self.assertRaises(ValueError):
            self.analyzer.domain_to_ascii('---invalid---.com')

    def test_emoji_domain_raises(self):
        with self.assertRaises((ValueError, Exception)):
            self.analyzer.domain_to_ascii('\U0001f480.com')


class TestDomainValidationEdgeCases(unittest.TestCase):

    def setUp(self):
        self.analyzer = create_test_analyzer()

    def test_empty_string_invalid(self):
        self.assertFalse(self.analyzer.validate_domain(''))

    def test_dot_only_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('.'))

    def test_single_label_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('localhost'))

    def test_url_with_protocol_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('https://example.com'))

    def test_url_with_path_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('example.com/path'))

    def test_leading_dot_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('.example.com'))

    def test_double_dot_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('example..com'))

    def test_hyphen_start_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('-example.com'))

    def test_long_domain_invalid(self):
        self.assertFalse(self.analyzer.validate_domain('a' * 250 + '.com'))

    def test_valid_subdomain(self):
        self.assertTrue(self.analyzer.validate_domain('sub.example.com'))

    def test_valid_hyphenated(self):
        self.assertTrue(self.analyzer.validate_domain('my-domain.com'))

    def test_valid_idn_punycode(self):
        self.assertTrue(self.analyzer.validate_domain('xn--mnchen-3ya.de'))

    def test_valid_unicode_domain(self):
        self.assertTrue(self.analyzer.validate_domain('münchen.de'))

    def test_numeric_labels_valid(self):
        self.assertTrue(self.analyzer.validate_domain('123.example.com'))


class TestSPFAnalysisEdgeCases(unittest.TestCase):

    def test_spf_no_record(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({
                ('TXT', 'no-spf.com'): ['some other txt record'],
            }),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_spf('no-spf.com')
        self.assertEqual(result['status'], 'error')
        self.assertIn('records', result)

    def test_spf_multiple_records_error(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({
                ('TXT', 'multi-spf.com'): ['v=spf1 -all', 'v=spf1 +all'],
            }),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_spf('multi-spf.com')
        self.assertIn(result['status'], ['error', 'warning'])

    def test_spf_result_has_required_fields(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({
                ('TXT', 'spf-test.com'): ['v=spf1 include:_spf.google.com ~all'],
            }),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_spf('spf-test.com')
        for field in ['status', 'message', 'records', 'valid_records', 'lookup_count', 'permissiveness', 'issues']:
            self.assertIn(field, result, f'SPF missing field: {field}')

    def test_spf_permissiveness_is_string(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({
                ('TXT', 'spf-perm.com'): ['v=spf1 +all'],
            }),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_spf('spf-perm.com')
        self.assertIsInstance(result.get('permissiveness'), str)


class TestDMARCAnalysisEdgeCases(unittest.TestCase):

    def test_dmarc_no_record(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({}),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_dmarc('no-dmarc.com')
        self.assertEqual(result['status'], 'error')

    def test_dmarc_policy_none(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({
                ('TXT', '_dmarc.dmarc-none.com'): ['v=DMARC1; p=none; rua=mailto:d@example.com'],
            }),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_dmarc('dmarc-none.com')
        self.assertIn(result['status'], ['success', 'warning'])
        self.assertEqual(result.get('policy'), 'none')

    def test_dmarc_policy_reject(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({
                ('TXT', '_dmarc.dmarc-reject.com'): ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
            }),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_dmarc('dmarc-reject.com')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result.get('policy'), 'reject')

    def test_dmarc_result_has_required_fields(self):
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({
                ('TXT', '_dmarc.dmarc-fields.com'): ['v=DMARC1; p=quarantine;'],
            }),
            http_client=make_http_client({}),
        )
        result = analyzer.analyze_dmarc('dmarc-fields.com')
        for field in ['status', 'message', 'policy', 'issues']:
            self.assertIn(field, result, f'DMARC missing field: {field}')


class TestBackpressure(unittest.TestCase):

    def test_backpressure_returns_error_structure(self):
        import threading
        analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver({}),
            http_client=make_http_client({}),
        )
        original_max = analyzer.MAX_CONCURRENT_ANALYSES
        analyzer.MAX_CONCURRENT_ANALYSES = 0
        analyzer._analysis_semaphore = threading.Semaphore(0)

        result = analyzer.analyze_domain('backpressure-test.com')
        self.assertIn('error', result)
        self.assertFalse(result.get('analysis_success', True))

        analyzer.MAX_CONCURRENT_ANALYSES = original_max
        analyzer._analysis_semaphore = threading.Semaphore(original_max)


class TestOutputConsistency(unittest.TestCase):

    def setUp(self):
        self.dns_records = {
            ('A', 'consistent.com'): ['1.2.3.4'],
            ('NS', 'consistent.com'): ['ns1.example.com.'],
            ('TXT', 'consistent.com'): ['v=spf1 -all'],
            ('MX', 'consistent.com'): [],
            ('AAAA', 'consistent.com'): [],
            ('CNAME', 'consistent.com'): [],
            ('SOA', 'consistent.com'): ['ns1.example.com. admin.example.com. 1 3600 900 604800 86400'],
            ('TXT', '_dmarc.consistent.com'): ['v=DMARC1; p=reject;'],
            ('CAA', 'consistent.com'): [],
        }
        self.analyzer = create_test_analyzer(
            dns_resolver=make_dns_resolver(self.dns_records),
            http_client=make_http_client({}),
        )

    def test_all_list_fields_are_lists(self):
        result = self.analyzer.analyze_domain('consistent.com')
        list_fields = [
            ('posture', 'issues'),
            ('posture', 'configured'),
            ('posture', 'absent'),
            ('posture', 'monitoring'),
            ('dane_analysis', 'tlsa_records'),
            ('dane_analysis', 'issues'),
        ]
        for section, field in list_fields:
            section_data = result.get(section, {})
            value = section_data.get(field)
            self.assertIsInstance(value, list, f'{section}.{field} should be list, got {type(value).__name__}')

    def test_all_bool_fields_are_bools(self):
        result = self.analyzer.analyze_domain('consistent.com')
        self.assertIsInstance(result.get('domain_exists'), bool)
        self.assertIsInstance(result.get('has_null_mx'), bool)
        self.assertIsInstance(result.get('is_no_mail_domain'), bool)
        dane = result.get('dane_analysis', {})
        self.assertIsInstance(dane.get('has_dane'), bool)

    def test_all_string_fields_are_strings(self):
        result = self.analyzer.analyze_domain('consistent.com')
        self.assertIsInstance(result.get('domain_status'), str)
        posture = result.get('posture', {})
        self.assertIsInstance(posture.get('state'), str)
        self.assertIsInstance(posture.get('color'), str)
        self.assertIsInstance(posture.get('message'), str)

    def test_schema_version_is_int(self):
        result = self.analyzer.analyze_domain('consistent.com')
        self.assertIsInstance(result.get('_schema_version'), int)
        self.assertEqual(result['_schema_version'], 2)

    def test_smtp_transport_is_none(self):
        result = self.analyzer.analyze_domain('consistent.com')
        self.assertIsNone(result.get('smtp_transport'))

    def test_data_freshness_is_dict(self):
        result = self.analyzer.analyze_domain('consistent.com')
        df = result.get('_data_freshness')
        self.assertIsInstance(df, dict)
        for key in ['dns_records', 'spf', 'dmarc', 'dkim', 'dane']:
            self.assertIn(key, df, f'_data_freshness missing: {key}')
            self.assertIsInstance(df[key], dict)


if __name__ == '__main__':
    unittest.main()
