import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.schema_contract import validate_analysis_results, get_required_sections


class TestStoredResults(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from app import app, db
        from app import DomainAnalysis
        cls.app = app
        cls.db = db
        cls.DomainAnalysis = DomainAnalysis
        cls.ctx = app.app_context()
        cls.ctx.push()

    @classmethod
    def tearDownClass(cls):
        cls.ctx.pop()

    def test_stored_results_validate(self):
        records = self.DomainAnalysis.query.filter(
            self.DomainAnalysis.full_results.isnot(None),
            self.DomainAnalysis.analysis_success == True,
        ).order_by(self.DomainAnalysis.id.desc()).limit(20).all()

        if not records:
            self.skipTest('No stored analysis records found in database.')

        v2_records = [
            r for r in records
            if r.full_results.get('_schema_version') == 2
            and '_tool_version' in r.full_results
            and '_data_freshness' in r.full_results
        ]
        if not v2_records:
            self.skipTest('No complete schema v2 records found in database.')

        for record in v2_records:
            errors = validate_analysis_results(record.full_results)
            self.assertEqual(
                errors, [],
                f'Validation errors for {record.domain} (id={record.id}): {errors}'
            )

    def test_stored_results_have_required_sections(self):
        records = self.DomainAnalysis.query.filter(
            self.DomainAnalysis.full_results.isnot(None),
            self.DomainAnalysis.analysis_success == True,
        ).limit(10).all()

        if not records:
            self.skipTest('No stored analysis records found.')

        required = get_required_sections()
        for record in records:
            results = record.full_results
            for section in required:
                self.assertIn(
                    section, results,
                    f'{record.domain} (id={record.id}): missing required section {section}'
                )

    def test_stored_results_schema_version(self):
        records = self.DomainAnalysis.query.filter(
            self.DomainAnalysis.full_results.isnot(None),
        ).order_by(self.DomainAnalysis.id.desc()).limit(10).all()

        if not records:
            self.skipTest('No stored records found.')

        checked = 0
        for record in records:
            results = record.full_results
            if '_schema_version' in results:
                self.assertIsInstance(results['_schema_version'], int)
                checked += 1

        if checked == 0:
            self.skipTest('No records with _schema_version found (legacy data only).')


class TestNormalizeResults(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from app import app
        from app import normalize_results
        cls.app = app
        cls.normalize_results = staticmethod(normalize_results)
        cls.ctx = app.app_context()
        cls.ctx.push()

    @classmethod
    def tearDownClass(cls):
        cls.ctx.pop()

    def test_normalize_none_returns_none(self):
        result = self.normalize_results(None)
        self.assertIsNone(result)

    def test_normalize_empty_dict_returns_none(self):
        result = self.normalize_results({})
        self.assertIsNone(result)

    def test_normalize_adds_missing_sections(self):
        partial = {
            '_schema_version': 2,
            'domain_exists': True,
            'basic_records': {'A': ['1.2.3.4']},
        }
        result = self.normalize_results(partial)
        self.assertIsNotNone(result)
        self.assertIn('spf_analysis', result)
        self.assertIn('dmarc_analysis', result)
        self.assertIn('posture', result)
        self.assertIn('dane_analysis', result)
        self.assertIn('mail_posture', result)

    def test_normalize_preserves_existing_data(self):
        full = {
            '_schema_version': 2,
            'domain_exists': True,
            'spf_analysis': {'status': 'success', 'records': ['v=spf1 -all']},
            'basic_records': {'A': ['1.2.3.4']},
        }
        result = self.normalize_results(full)
        self.assertEqual(result['spf_analysis']['status'], 'success')
        self.assertEqual(result['spf_analysis']['records'], ['v=spf1 -all'])

    def test_normalize_output_has_default_sections(self):
        minimal = {'_schema_version': 2, 'domain_exists': True}
        result = self.normalize_results(minimal)
        expected_defaults = [
            'spf_analysis', 'dmarc_analysis', 'dkim_analysis',
            'registrar_info', 'posture', 'dane_analysis',
            'mta_sts_analysis', 'tlsrpt_analysis', 'bimi_analysis',
            'caa_analysis', 'dnssec_analysis', 'ct_subdomains',
            'mail_posture', '_data_freshness',
        ]
        for section in expected_defaults:
            self.assertIn(section, result, f'normalize_results missing default: {section}')


class TestEdgeCases(unittest.TestCase):

    def test_empty_results_fail_validation(self):
        errors = validate_analysis_results({})
        self.assertGreater(len(errors), 0)

    def test_missing_all_sections(self):
        results = {
            'domain_exists': True,
            'domain_status': 'active',
            'domain_status_message': None,
            '_schema_version': 2,
            '_tool_version': '26.10.81',
        }
        errors = validate_analysis_results(results)
        required = get_required_sections()
        for section in required:
            has_error = any(section in e for e in errors)
            self.assertTrue(has_error, f'Should report missing section: {section}')

    def test_partial_results_report_specific_errors(self):
        results = {
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
            'spf_analysis': {'status': 'success'},
            'dmarc_analysis': {'status': 'success'},
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
                'message': 'All good',
                'issues': [],
                'configured': [],
                'absent': [],
                'monitoring': [],
                'verdicts': {},
            },
            '_schema_version': 2,
            '_tool_version': '26.10.81',
        }
        errors = validate_analysis_results(results)
        self.assertEqual(errors, [], f'Full valid result should pass: {errors}')

    def test_wrong_type_detected(self):
        results = {
            'domain_exists': 'yes',
        }
        errors = validate_analysis_results(results)
        self.assertTrue(any('domain_exists' in e and 'type' in e.lower() for e in errors))

    def test_non_dict_input(self):
        errors = validate_analysis_results([])
        self.assertIn('Results must be a dictionary', errors)


if __name__ == '__main__':
    unittest.main()
