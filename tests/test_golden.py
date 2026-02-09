import unittest
import sys
import os
import json
import glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.schema_contract import (
    validate_analysis_results,
    get_required_sections,
    VALID_STATUS_VALUES,
    ANALYSIS_SCHEMA,
)

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'golden_fixtures')

VOLATILE_KEYS = {
    '_captured_at', '_captured_version', '_data_freshness',
    'analysis_duration', 'resolver_ttl', 'auth_ttl',
}

VOLATILE_VALUE_KEYS = {
    'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA',
    'registrar', 'created_date', 'expiry_date', 'updated_date',
    'ip_addresses', 'nameservers',
}


def load_fixtures():
    fixtures = {}
    if not os.path.isdir(FIXTURES_DIR):
        return fixtures
    for filepath in glob.glob(os.path.join(FIXTURES_DIR, '*.json')):
        basename = os.path.basename(filepath)
        if basename == 'manifest.json':
            continue
        with open(filepath, 'r') as f:
            fixtures[basename] = json.load(f)
    return fixtures


class TestSchemaContract(unittest.TestCase):

    def test_required_sections_list(self):
        sections = get_required_sections()
        self.assertIsInstance(sections, list)
        self.assertGreater(len(sections), 0)
        expected = [
            'basic_records', 'spf_analysis', 'dmarc_analysis',
            'dkim_analysis', 'registrar_info', 'posture',
            'dane_analysis', 'mta_sts_analysis', 'tlsrpt_analysis',
            'bimi_analysis', 'caa_analysis', 'dnssec_analysis',
        ]
        for section in expected:
            self.assertIn(section, sections)

    def test_schema_has_all_required_sections(self):
        for section in get_required_sections():
            self.assertIn(section, ANALYSIS_SCHEMA, f'Schema missing required section: {section}')

    def test_posture_scoring_valid_range(self):
        fixtures = load_fixtures()
        for name, data in fixtures.items():
            posture = data.get('posture', {})
            if 'score' in posture:
                score = posture['score']
                self.assertIsInstance(score, (int, float), f'{name}: posture score should be numeric')
                self.assertGreaterEqual(score, 0, f'{name}: score below 0')
                self.assertLessEqual(score, 100, f'{name}: score above 100')

    def test_status_fields_have_valid_values(self):
        fixtures = load_fixtures()
        status_sections = [
            'spf_analysis', 'dmarc_analysis', 'dkim_analysis',
            'dane_analysis', 'mta_sts_analysis', 'tlsrpt_analysis',
            'bimi_analysis', 'caa_analysis', 'dnssec_analysis',
        ]
        for name, data in fixtures.items():
            for section in status_sections:
                section_data = data.get(section, {})
                if isinstance(section_data, dict) and 'status' in section_data:
                    status = section_data['status']
                    self.assertIn(
                        status, VALID_STATUS_VALUES,
                        f'{name}/{section}: invalid status "{status}"'
                    )

    def test_schema_version_present(self):
        fixtures = load_fixtures()
        for name, data in fixtures.items():
            self.assertIn('_schema_version', data, f'{name}: missing _schema_version')
            self.assertIsInstance(data['_schema_version'], int, f'{name}: _schema_version must be int')
            self.assertEqual(data['_schema_version'], 2, f'{name}: expected schema version 2')

    def test_validate_empty_results_returns_errors(self):
        errors = validate_analysis_results({})
        self.assertGreater(len(errors), 0)

    def test_validate_non_dict_returns_errors(self):
        errors = validate_analysis_results("not a dict")
        self.assertIn('Results must be a dictionary', errors)


class TestGoldenFixtures(unittest.TestCase):

    def test_fixtures_load(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found. Run golden_fixture_capture.py first.')

    def test_each_fixture_passes_schema_validation(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            errors = validate_analysis_results(data)
            self.assertEqual(errors, [], f'{name} schema validation errors: {errors}')

    def test_required_sections_present_in_fixtures(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            for section in get_required_sections():
                self.assertIn(section, data, f'{name}: missing required section {section}')

    def test_spf_has_status(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            spf = data.get('spf_analysis', {})
            self.assertIn('status', spf, f'{name}: spf_analysis missing status')

    def test_dmarc_has_policy_on_success(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            dmarc = data.get('dmarc_analysis', {})
            if dmarc.get('status') in ('success', 'warning'):
                self.assertIn('policy', dmarc, f'{name}: dmarc_analysis missing policy field on success')

    def test_dane_structure(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            dane = data.get('dane_analysis', {})
            self.assertIn('status', dane, f'{name}: dane_analysis missing status')
            self.assertIn('has_dane', dane, f'{name}: dane_analysis missing has_dane')
            self.assertIn('tlsa_records', dane, f'{name}: dane_analysis missing tlsa_records')
            self.assertIn('issues', dane, f'{name}: dane_analysis missing issues')

    def test_posture_graduated_assessment(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            posture = data.get('posture', {})
            domain_exists = data.get('domain_exists', True)
            if domain_exists:
                has_state = 'state' in posture
                has_configured = 'configured' in posture
                has_absent = 'absent' in posture
                has_monitoring = 'monitoring' in posture
                self.assertTrue(
                    has_state and has_configured and has_absent and has_monitoring,
                    f'{name}: posture missing graduated assessment fields (state/configured/absent/monitoring)'
                )
            else:
                self.assertIn('score', posture, f'{name}: non-existent domain posture missing score')
                self.assertIn('grade', posture, f'{name}: non-existent domain posture missing grade')
                self.assertIn('label', posture, f'{name}: non-existent domain posture missing label')

    def test_mail_posture_classification(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            mp = data.get('mail_posture', {})
            self.assertIn('classification', mp, f'{name}: mail_posture missing classification')

    def test_hosting_summary_fields(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            hs = data.get('hosting_summary', {})
            for field in ('hosting', 'dns_hosting', 'email_hosting'):
                self.assertIn(field, hs, f'{name}: hosting_summary missing {field}')


def _make_key_path(path, key):
    return f'{path}.{key}' if path else key


def _report_key_diff(differences, path, key, direction):
    full_path = _make_key_path(path, key)
    differences.append(f'{direction} key in fresh: {full_path}')


def _compare_common_key(golden, fresh, key, path, differences, compare_fn):
    if key in VOLATILE_KEYS or key in VOLATILE_VALUE_KEYS:
        return
    child_path = _make_key_path(path, key)
    g_val = golden[key]
    f_val = fresh[key]
    if type(g_val) != type(f_val) and not (g_val is None or f_val is None):
        differences.append(f'Type changed at {child_path}: {type(g_val).__name__} -> {type(f_val).__name__}')
        return
    if isinstance(g_val, dict):
        compare_fn(g_val, f_val, child_path, differences)


def _compare_dict_structures(golden, fresh, path, differences):
    golden_keys = set(golden.keys())
    fresh_keys = set(fresh.keys())

    for key in golden_keys - fresh_keys - VOLATILE_KEYS:
        _report_key_diff(differences, path, key, 'Missing')

    for key in fresh_keys - golden_keys - VOLATILE_KEYS:
        _report_key_diff(differences, path, key, 'New')

    for key in golden_keys & fresh_keys:
        _compare_common_key(golden, fresh, key, path, differences, _compare_dict_structures)


def _compare_structure(golden, fresh, path, differences):
    both_dicts = isinstance(golden, dict) and isinstance(fresh, dict)
    if both_dicts:
        _compare_dict_structures(golden, fresh, path, differences)
        return

    golden_is_dict = isinstance(golden, dict)
    fresh_is_dict = isinstance(fresh, dict)
    if golden_is_dict and not fresh_is_dict:
        differences.append(f'Type changed at {path}: dict -> {type(fresh).__name__}')
    elif not golden_is_dict and fresh_is_dict:
        differences.append(f'Type changed at {path}: {type(golden).__name__} -> dict')


class TestAnalysisRegression(unittest.TestCase):

    def compare_analysis_outputs(self, golden, fresh):
        differences = []
        _compare_structure(golden, fresh, '', differences)
        return differences

    def test_regression_self_comparison(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            diffs = self.compare_analysis_outputs(data, data)
            self.assertEqual(diffs, [], f'{name}: self-comparison should produce no differences')

    def test_regression_detects_missing_section(self):
        sample = {
            'domain_exists': True,
            'posture': {'state': 'STRONG', 'color': 'success', 'issues': [], 'configured': [], 'absent': [], 'monitoring': [], 'verdicts': {}},
            'spf_analysis': {'status': 'success'},
        }
        modified = {'domain_exists': True, 'posture': sample['posture']}
        diffs = self.compare_analysis_outputs(sample, modified)
        self.assertTrue(any('spf_analysis' in d for d in diffs))

    def test_regression_detects_type_change(self):
        golden = {'domain_exists': True, 'spf_analysis': {'status': 'success'}}
        fresh = {'domain_exists': True, 'spf_analysis': 'broken'}
        diffs = self.compare_analysis_outputs(golden, fresh)
        self.assertTrue(any('Type changed' in d for d in diffs))


if __name__ == '__main__':
    unittest.main()
