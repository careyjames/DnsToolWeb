import unittest
import sys
import os
import json
import glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.schema_contract import (
    validate_analysis_results,
    validate_analysis_deep,
    get_required_sections,
    VALID_STATUS_VALUES,
    ANALYSIS_SCHEMA,
    SCHEMA_ACTIVE_DOMAIN_REQUIRED,
    EMAIL_SECURITY_PROVIDER_REQUIRED_FIELDS,
)
from tests.feature_parity_manifest import (
    FEATURE_PARITY_MANIFEST,
    REQUIRED_SCHEMA_KEYS,
    get_manifest_by_category,
    get_all_detection_methods,
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


CURATED_DOMAINS = [
    "google.com",
    "example.com",
    "thisdoesnotexist-xz9q.com",
    "whitehouse.gov",
    "cloudflare.com",
]


DOMAIN_BEHAVIORAL_EXPECTATIONS = {
    'google_com.json': {
        'domain_exists': True,
        'has_spf': True,
        'has_dmarc': True,
        'dmarc_policy_in': ['reject', 'quarantine'],
        'posture_state_in': ['STRONG', 'GOOD'],
        'dns_infra_provider_not_empty': True,
    },
    'example_com.json': {
        'domain_exists': True,
    },
    'cloudflare_com.json': {
        'domain_exists': True,
        'has_spf': True,
        'has_dmarc': True,
        'dns_infra_provider_not_empty': True,
        'posture_state_in': ['STRONG', 'GOOD', 'FAIR'],
    },
    'whitehouse_gov.json': {
        'domain_exists': True,
        'has_spf': True,
        'has_dmarc': True,
        'dmarc_policy_in': ['reject', 'quarantine'],
    },
    'thisdoesnotexist-xz9q_com.json': {
        'domain_exists': False,
    },
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

    def test_schema_catches_empty_email_security_mgmt(self):
        errors = validate_analysis_results({'email_security_mgmt': {}})
        esm_errors = [e for e in errors if 'email_security_mgmt' in e]
        self.assertGreater(len(esm_errors), 0,
                           'Empty email_security_mgmt dict should produce validation errors')

    def test_schema_catches_empty_dns_infrastructure(self):
        errors = validate_analysis_results({'dns_infrastructure': {}})
        di_errors = [e for e in errors if 'dns_infrastructure' in e]
        self.assertGreater(len(di_errors), 0,
                           'Empty dns_infrastructure dict should produce validation errors')

    def test_schema_catches_empty_resolver_consensus(self):
        errors = validate_analysis_results({'resolver_consensus': {}})
        rc_errors = [e for e in errors if 'resolver_consensus' in e]
        self.assertGreater(len(rc_errors), 0,
                           'Empty resolver_consensus dict should produce validation errors')

    def test_schema_catches_empty_ns_delegation(self):
        errors = validate_analysis_results({'ns_delegation_analysis': {}})
        ns_errors = [e for e in errors if 'ns_delegation_analysis' in e]
        self.assertGreater(len(ns_errors), 0,
                           'Empty ns_delegation_analysis dict should produce validation errors')

    def test_schema_catches_actively_managed_without_providers(self):
        esm = {
            'actively_managed': True,
            'provider_count': 0,
            'providers': [],
        }
        errors = validate_analysis_results({'email_security_mgmt': esm})
        esm_errors = [e for e in errors if 'actively_managed' in e or 'provider_count' in e]
        self.assertGreater(len(esm_errors), 0,
                           'actively_managed=True with 0 providers should produce errors')

    def test_schema_validates_provider_objects(self):
        esm = {
            'actively_managed': True,
            'provider_count': 1,
            'providers': [{}],
        }
        errors = validate_analysis_results({'email_security_mgmt': esm})
        provider_errors = [e for e in errors if 'providers[0]' in e]
        self.assertGreater(len(provider_errors), 0,
                           'Provider missing required fields should produce errors')

    def test_schema_provider_count_mismatch(self):
        esm = {
            'actively_managed': False,
            'provider_count': 5,
            'providers': [],
        }
        errors = validate_analysis_results({'email_security_mgmt': esm})
        mismatch_errors = [e for e in errors if 'does not match' in e]
        self.assertGreater(len(mismatch_errors), 0,
                           'provider_count mismatch should produce errors')


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

    def test_each_fixture_passes_deep_validation(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            errors = validate_analysis_deep(data)
            self.assertEqual(errors, [], f'{name} deep validation errors: {errors}')

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

    def test_mail_posture_verdict(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            mp = data.get('mail_posture', {})
            if mp is None:
                self.fail(f'{name}: mail_posture is null for active domain')
            self.assertIn('verdict', mp, f'{name}: mail_posture missing verdict')
            self.assertIn('badge', mp, f'{name}: mail_posture missing badge')

    def test_hosting_summary_fields(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            hs = data.get('hosting_summary', {})
            for field in ('hosting', 'dns_hosting', 'email_hosting'):
                self.assertIn(field, hs, f'{name}: hosting_summary missing {field}')

    def test_email_security_mgmt_structure(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            esm = data.get('email_security_mgmt', {})
            if esm is None:
                self.fail(f'{name}: email_security_mgmt is null for active domain')
            self.assertIn('actively_managed', esm, f'{name}: email_security_mgmt missing actively_managed')
            self.assertIn('provider_count', esm, f'{name}: email_security_mgmt missing provider_count')
            self.assertIn('providers', esm, f'{name}: email_security_mgmt missing providers')
            self.assertIsInstance(esm.get('providers', None), list,
                                 f'{name}: email_security_mgmt.providers must be a list')
            for i, provider in enumerate(esm.get('providers', [])):
                self.assertIsInstance(provider, dict, f'{name}: provider[{i}] must be a dict')
                for field in EMAIL_SECURITY_PROVIDER_REQUIRED_FIELDS:
                    self.assertIn(field, provider, f'{name}: provider[{i}] missing {field}')

    def test_dns_infrastructure_structure(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            di = data.get('dns_infrastructure', {})
            if di is None:
                self.fail(f'{name}: dns_infrastructure is null for active domain')
            self.assertIn('provider_name', di, f'{name}: dns_infrastructure missing provider_name')
            self.assertIn('provider_tier', di, f'{name}: dns_infrastructure missing provider_tier')
            self.assertIn('provider_features', di, f'{name}: dns_infrastructure missing provider_features')

    def test_resolver_consensus_structure(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            rc = data.get('resolver_consensus', {})
            if rc is None:
                self.fail(f'{name}: resolver_consensus is null for active domain')
            self.assertIn('consensus_reached', rc, f'{name}: resolver_consensus missing consensus_reached')
            self.assertIn('resolvers_queried', rc, f'{name}: resolver_consensus missing resolvers_queried')
            self.assertIn('per_record_consensus', rc, f'{name}: resolver_consensus missing per_record_consensus')

    def test_ns_delegation_structure(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            nsd = data.get('ns_delegation_analysis', {})
            self.assertIn('status', nsd, f'{name}: ns_delegation_analysis missing status')
            self.assertIn('delegation_ok', nsd, f'{name}: ns_delegation_analysis missing delegation_ok')

    def test_ct_subdomains_structure(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            ct = data.get('ct_subdomains', {})
            if ct is None:
                self.fail(f'{name}: ct_subdomains is null for active domain')
            self.assertIn('status', ct, f'{name}: ct_subdomains missing status')
            self.assertIn('subdomains', ct, f'{name}: ct_subdomains missing subdomains')
            self.assertIn('unique_subdomains', ct, f'{name}: ct_subdomains missing unique_subdomains')

    def test_basic_records_has_all_types(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        from tests.schema_contract import BASIC_RECORD_TYPES
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            br = data.get('basic_records', {})
            for rt in BASIC_RECORD_TYPES:
                self.assertIn(rt, br, f'{name}: basic_records missing record type {rt}')


class TestBehavioralExpectations(unittest.TestCase):

    def test_behavioral_expectations_for_known_domains(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')

        for fixture_name, expectations in DOMAIN_BEHAVIORAL_EXPECTATIONS.items():
            if fixture_name not in fixtures:
                continue
            data = fixtures[fixture_name]

            if 'domain_exists' in expectations:
                self.assertEqual(
                    data.get('domain_exists'),
                    expectations['domain_exists'],
                    f'{fixture_name}: domain_exists mismatch'
                )

            if expectations.get('has_spf'):
                spf = data.get('spf_analysis', {})
                self.assertIn(spf.get('status'), ('success', 'warning'),
                              f'{fixture_name}: expected SPF to be present')

            if expectations.get('has_dmarc'):
                dmarc = data.get('dmarc_analysis', {})
                self.assertIn(dmarc.get('status'), ('success', 'warning'),
                              f'{fixture_name}: expected DMARC to be present')

            if 'dmarc_policy_in' in expectations:
                dmarc = data.get('dmarc_analysis', {})
                policy = dmarc.get('policy')
                self.assertIn(policy, expectations['dmarc_policy_in'],
                              f'{fixture_name}: DMARC policy "{policy}" not in expected {expectations["dmarc_policy_in"]}')

            if 'posture_state_in' in expectations:
                posture = data.get('posture', {})
                state = posture.get('state')
                self.assertIn(state, expectations['posture_state_in'],
                              f'{fixture_name}: posture state "{state}" not in expected {expectations["posture_state_in"]}')

            if expectations.get('has_email_security_providers'):
                esm = data.get('email_security_mgmt', {})
                self.assertTrue(esm.get('actively_managed'),
                                f'{fixture_name}: expected actively_managed=True')
                self.assertGreater(esm.get('provider_count', 0), 0,
                                   f'{fixture_name}: expected provider_count > 0')
                self.assertGreater(len(esm.get('providers', [])), 0,
                                   f'{fixture_name}: expected non-empty providers list')

            if expectations.get('dns_infra_provider_not_empty'):
                di = data.get('dns_infrastructure', {})
                if di is None:
                    self.fail(f'{fixture_name}: dns_infrastructure is null')
                provider = di.get('provider_name', '') or di.get('provider', '')
                self.assertTrue(len(provider) > 0,
                                f'{fixture_name}: expected dns_infrastructure provider to be non-empty')

            if expectations.get('is_no_mail_domain'):
                self.assertTrue(data.get('is_no_mail_domain'),
                                f'{fixture_name}: expected is_no_mail_domain=True')

    def test_email_security_providers_have_detection_sources(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            esm = data.get('email_security_mgmt', {})
            for i, provider in enumerate(esm.get('providers', [])):
                detected = provider.get('detected_from', [])
                self.assertGreater(len(detected), 0,
                                   f'{name}: provider[{i}] ({provider.get("name", "?")}) has empty detected_from')
                caps = provider.get('capabilities', [])
                self.assertGreater(len(caps), 0,
                                   f'{name}: provider[{i}] ({provider.get("name", "?")}) has empty capabilities')


class TestFixtureCompleteness(unittest.TestCase):

    def test_fixture_manifest_matches_curated_domains(self):
        manifest_path = os.path.join(FIXTURES_DIR, 'manifest.json')
        if not os.path.exists(manifest_path):
            self.skipTest('No manifest.json found.')
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        for domain in CURATED_DOMAINS:
            self.assertIn(domain, manifest.get('domains', []),
                          f'Curated domain {domain} missing from manifest')

    def test_all_curated_domains_have_fixture_files(self):
        if not os.path.isdir(FIXTURES_DIR):
            self.skipTest('No fixtures directory found.')
        for domain in CURATED_DOMAINS:
            filename = domain.replace('.', '_').replace('/', '_').replace(':', '_') + '.json'
            filepath = os.path.join(FIXTURES_DIR, filename)
            self.assertTrue(
                os.path.exists(filepath),
                f'Missing fixture file for curated domain {domain}: expected {filename}'
            )


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

    def test_regression_detects_missing_email_security_mgmt_fields(self):
        golden = {
            'email_security_mgmt': {
                'actively_managed': True,
                'provider_count': 1,
                'providers': [{'name': 'Agari', 'capabilities': ['DMARC'], 'detected_from': ['DMARC rua']}],
            }
        }
        fresh = {
            'email_security_mgmt': {}
        }
        diffs = self.compare_analysis_outputs(golden, fresh)
        self.assertGreater(len(diffs), 0,
                           'Missing email_security_mgmt subfields should be detected as structural differences')


class TestFeatureParityManifest(unittest.TestCase):

    def test_manifest_covers_all_schema_keys(self):
        all_schema_keys = set(ANALYSIS_SCHEMA.keys()) | set(SCHEMA_ACTIVE_DOMAIN_REQUIRED.keys())
        internal_keys = {'_schema_version', '_tool_version'}
        testable_keys = all_schema_keys - internal_keys
        manifest_keys = set(REQUIRED_SCHEMA_KEYS)
        missing_from_manifest = testable_keys - manifest_keys
        self.assertEqual(
            missing_from_manifest, set(),
            f'Schema keys not covered by feature parity manifest: {missing_from_manifest}'
        )

    def test_manifest_schema_keys_exist_in_schema(self):
        all_schema_keys = set(ANALYSIS_SCHEMA.keys()) | set(SCHEMA_ACTIVE_DOMAIN_REQUIRED.keys())
        special_keys = {'domain_exists', '_data_freshness', 'auth_query_status', 'resolver_ttl', 'auth_ttl'}
        for feature in FEATURE_PARITY_MANIFEST:
            key = feature['schema_key']
            schema_or_special = key in all_schema_keys or key in special_keys
            self.assertTrue(
                schema_or_special,
                f'Manifest feature "{feature["feature"]}" references schema_key "{key}" not in any schema'
            )

    def test_every_feature_has_detection_methods(self):
        for feature in FEATURE_PARITY_MANIFEST:
            methods = feature.get('detection_methods', [])
            self.assertGreater(
                len(methods), 0,
                f'Feature "{feature["feature"]}" has no detection_methods listed'
            )

    def test_detection_categories_are_valid(self):
        valid_categories = {'analysis', 'detection', 'infrastructure', 'assessment'}
        for feature in FEATURE_PARITY_MANIFEST:
            self.assertIn(
                feature['category'], valid_categories,
                f'Feature "{feature["feature"]}" has invalid category "{feature["category"]}"'
            )

    def test_analysis_features_have_rfc(self):
        for feature in get_manifest_by_category('analysis'):
            self.assertIn(
                'rfc', feature,
                f'Analysis feature "{feature["feature"]}" should reference an RFC'
            )
            self.assertTrue(
                feature['rfc'].startswith('RFC'),
                f'Analysis feature "{feature["feature"]}" RFC should start with "RFC"'
            )

    def test_email_security_mgmt_detection_methods_comprehensive(self):
        feature = None
        for f in FEATURE_PARITY_MANIFEST:
            if f['schema_key'] == 'email_security_mgmt':
                feature = f
                break
        self.assertIsNotNone(feature, 'email_security_mgmt not found in manifest')
        methods = feature['detection_methods']
        self.assertTrue(
            any('DMARC rua' in m for m in methods),
            'email_security_mgmt must include DMARC rua provider matching'
        )
        self.assertTrue(
            any('SPF' in m and 'flatten' in m.lower() for m in methods),
            'email_security_mgmt must include SPF flattening detection'
        )
        self.assertTrue(
            any('DKIM' in m and 'CNAME' in m for m in methods),
            'email_security_mgmt must include hosted DKIM CNAME detection'
        )
        self.assertTrue(
            any('dynamic' in m.lower() or 'NS delegation' in m for m in methods),
            'email_security_mgmt must include dynamic services NS delegation detection'
        )
        self.assertTrue(
            any('CNAME provider' in m for m in methods),
            'email_security_mgmt must include CNAME provider mapping'
        )

    def test_minimum_feature_count(self):
        self.assertGreaterEqual(
            len(FEATURE_PARITY_MANIFEST), 20,
            'Feature parity manifest should have at least 20 features'
        )

    def test_minimum_detection_methods(self):
        all_methods = get_all_detection_methods()
        self.assertGreaterEqual(
            len(all_methods), 50,
            f'Feature parity manifest should enumerate at least 50 detection methods (found {len(all_methods)})'
        )

    def test_golden_fixtures_cover_manifest_keys(self):
        fixtures = load_fixtures()
        if not fixtures:
            self.skipTest('No golden fixtures found.')
        for name, data in fixtures.items():
            if not data.get('domain_exists', True):
                continue
            for key in REQUIRED_SCHEMA_KEYS:
                if key in ('domain_exists', '_data_freshness'):
                    continue
                self.assertIn(key, data, f'{name}: missing manifest-required key {key}')


if __name__ == '__main__':
    unittest.main()
