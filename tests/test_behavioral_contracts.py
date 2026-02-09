"""
Behavioral contract tests for DNS analysis logic.
Verifies that the graduated, RFC-backed assessment logic
produces correct verdicts — critical for Go migration parity.
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.schema_contract import (
    validate_analysis_results,
    validate_analysis_deep,
    VALID_STATUS_VALUES,
    VALID_POSTURE_STATES,
    VALID_POSTURE_COLORS,
    VALID_MAIL_CLASSIFICATIONS,
)


class TestPostureStateContract(unittest.TestCase):

    def test_posture_states_are_exhaustive(self):
        self.assertEqual(
            VALID_POSTURE_STATES,
            {'STRONG', 'GOOD', 'MODERATE', 'WEAK', 'CRITICAL'}
        )

    def test_posture_colors_are_exhaustive(self):
        self.assertEqual(
            VALID_POSTURE_COLORS,
            {'success', 'info', 'warning', 'danger', 'secondary'}
        )

    def test_status_values_include_all_expected(self):
        expected = {'success', 'warning', 'error', 'info', 'n/a', 'timeout', 'unknown', 'partial'}
        self.assertEqual(VALID_STATUS_VALUES, expected)


class TestMailClassificationContract(unittest.TestCase):

    def test_classifications_include_email_types(self):
        self.assertIn('email_enabled', VALID_MAIL_CLASSIFICATIONS)
        self.assertIn('email_minimal', VALID_MAIL_CLASSIFICATIONS)

    def test_classifications_include_no_mail_types(self):
        self.assertIn('no_mail_verified', VALID_MAIL_CLASSIFICATIONS)
        self.assertIn('no_mail_partial', VALID_MAIL_CLASSIFICATIONS)


class TestScorecardVerdictLogic(unittest.TestCase):

    def _email_spoofing_verdict(self, spf_status, dmarc_status, dmarc_policy):
        spf_ok = spf_status == 'success'
        dmarc_ok = dmarc_status == 'success'
        dmarc_enforced = dmarc_policy in ['reject', 'quarantine']

        if spf_ok and dmarc_ok and dmarc_enforced:
            return 'protected'
        elif spf_ok and dmarc_ok and dmarc_policy == 'none':
            return 'monitoring'
        elif spf_ok or dmarc_ok:
            return 'partial'
        return 'vulnerable'

    def test_full_protection(self):
        self.assertEqual(self._email_spoofing_verdict('success', 'success', 'reject'), 'protected')
        self.assertEqual(self._email_spoofing_verdict('success', 'success', 'quarantine'), 'protected')

    def test_monitoring_mode(self):
        self.assertEqual(self._email_spoofing_verdict('success', 'success', 'none'), 'monitoring')

    def test_partial_spf_only(self):
        self.assertEqual(self._email_spoofing_verdict('success', 'error', None), 'partial')

    def test_partial_dmarc_only(self):
        self.assertEqual(self._email_spoofing_verdict('error', 'success', 'reject'), 'partial')

    def test_fully_vulnerable(self):
        self.assertEqual(self._email_spoofing_verdict('error', 'error', None), 'vulnerable')

    def test_warning_spf_is_vulnerable(self):
        self.assertEqual(self._email_spoofing_verdict('warning', 'error', None), 'vulnerable')

    def _brand_impersonation_verdict(self, bimi_status, vmc_valid):
        if bimi_status == 'success' and vmc_valid:
            return 'protected'
        elif bimi_status == 'success':
            return 'basic'
        return 'not_setup'

    def test_bimi_protected(self):
        self.assertEqual(self._brand_impersonation_verdict('success', True), 'protected')

    def test_bimi_basic(self):
        self.assertEqual(self._brand_impersonation_verdict('success', False), 'basic')

    def test_bimi_not_setup(self):
        self.assertEqual(self._brand_impersonation_verdict('error', False), 'not_setup')

    def _dns_tampering_verdict(self, dnssec_status, provider_tier):
        if dnssec_status == 'success':
            return 'protected'
        elif provider_tier == 'enterprise':
            return 'enterprise'
        return 'unsigned'

    def test_dnssec_protected(self):
        self.assertEqual(self._dns_tampering_verdict('success', 'standard'), 'protected')

    def test_enterprise_without_dnssec(self):
        self.assertEqual(self._dns_tampering_verdict('error', 'enterprise'), 'enterprise')

    def test_unsigned_standard(self):
        self.assertEqual(self._dns_tampering_verdict('error', 'standard'), 'unsigned')


class TestDeepValidation(unittest.TestCase):

    def _make_valid_result(self, **overrides):
        result = {
            'domain_exists': True,
            'domain_status': 'active',
            'domain_status_message': None,
            'section_status': {},
            'basic_records': {},
            'authoritative_records': {},
            'auth_query_status': {},
            'resolver_ttl': {},
            'auth_ttl': {},
            'propagation_status': {},
            'spf_analysis': {'status': 'success', 'lookup_count': 3, 'permissiveness': 'strict'},
            'dmarc_analysis': {'status': 'success', 'policy': 'reject'},
            'dkim_analysis': {'status': 'success'},
            'mta_sts_analysis': {'status': 'success'},
            'tlsrpt_analysis': {'status': 'success'},
            'bimi_analysis': {'status': 'success'},
            'dane_analysis': {'status': 'success', 'has_dane': False, 'tlsa_records': [], 'issues': []},
            'caa_analysis': {'status': 'success'},
            'dnssec_analysis': {'status': 'success'},
            'ns_delegation_analysis': {},
            'registrar_info': {},
            'resolver_consensus': {},
            'ct_subdomains': {},
            'smtp_transport': None,
            '_data_freshness': {},
            'has_null_mx': False,
            'mail_posture': {'classification': 'email_enabled'},
            'is_no_mail_domain': False,
            'hosting_summary': {'hosting': 'Test', 'dns_hosting': 'Test', 'email_hosting': 'Test'},
            'dns_infrastructure': {},
            'email_security_mgmt': {},
            'posture': {
                'state': 'STRONG',
                'color': 'success',
                'message': 'Excellent security posture',
                'issues': [],
                'configured': ['SPF', 'DMARC'],
                'absent': [],
                'monitoring': [],
                'verdicts': {},
            },
            '_schema_version': 2,
            '_tool_version': '26.10.85',
        }
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key].update(value)
            else:
                result[key] = value
        return result

    def test_valid_full_result_passes(self):
        errors = validate_analysis_deep(self._make_valid_result())
        self.assertEqual(errors, [], f'Should pass deep validation: {errors}')

    def test_invalid_posture_state_detected(self):
        result = self._make_valid_result(posture={
            'state': 'SUPER_STRONG',
            'color': 'success',
            'message': 'test',
            'issues': [],
            'configured': [],
            'absent': [],
            'monitoring': [],
            'verdicts': {},
        })
        errors = validate_analysis_deep(result)
        self.assertTrue(any('posture state' in e.lower() for e in errors))

    def test_invalid_posture_color_detected(self):
        result = self._make_valid_result(posture={
            'state': 'STRONG',
            'color': 'purple',
            'message': 'test',
            'issues': [],
            'configured': [],
            'absent': [],
            'monitoring': [],
            'verdicts': {},
        })
        errors = validate_analysis_deep(result)
        self.assertTrue(any('posture color' in e.lower() for e in errors))

    def test_invalid_dmarc_policy_detected(self):
        result = self._make_valid_result(
            dmarc_analysis={'status': 'success', 'policy': 'invalid_policy'}
        )
        errors = validate_analysis_deep(result)
        self.assertTrue(any('DMARC policy' in e for e in errors))

    def test_invalid_mail_classification_detected(self):
        result = self._make_valid_result(
            mail_posture={'classification': 'totally_invalid'}
        )
        errors = validate_analysis_deep(result)
        self.assertTrue(any('mail_posture classification' in e for e in errors))

    def test_negative_spf_lookup_count_detected(self):
        result = self._make_valid_result(
            spf_analysis={'status': 'success', 'lookup_count': -1}
        )
        errors = validate_analysis_deep(result)
        self.assertTrue(any('SPF lookup_count' in e for e in errors))


if __name__ == '__main__':
    unittest.main()
