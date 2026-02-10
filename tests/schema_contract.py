import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REQUIRED_SECTIONS = [
    'basic_records', 'spf_analysis', 'dmarc_analysis',
    'dkim_analysis', 'registrar_info', 'posture',
    'dane_analysis', 'mta_sts_analysis', 'tlsrpt_analysis',
    'bimi_analysis', 'caa_analysis', 'dnssec_analysis',
]

BASIC_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']

ANALYSIS_SCHEMA = {
    'domain_exists': {'type': bool, 'required': True},
    'domain_status': {'type': str, 'required': True},
    'domain_status_message': {'type': (str, type(None)), 'required': True},
    'section_status': {'type': dict, 'required': True},
    'basic_records': {
        'type': dict,
        'required': True,
        'required_keys': BASIC_RECORD_TYPES,
    },
    'authoritative_records': {'type': dict, 'required': True},
    'propagation_status': {
        'type': dict,
        'required': True,
    },
    'spf_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'dmarc_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'dkim_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'mta_sts_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'tlsrpt_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'bimi_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'dane_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
            'has_dane': {'type': bool, 'required': True},
            'tlsa_records': {'type': (list, type(None)), 'required': True},
            'issues': {'type': (list, type(None)), 'required': True},
        },
    },
    'caa_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'dnssec_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
        },
    },
    'ns_delegation_analysis': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
            'delegation_ok': {'type': bool, 'required': True},
            'child_ns': {'type': (list, type(None)), 'required': False},
            'parent_ns': {'type': (list, type(None)), 'required': False},
        },
    },
    'registrar_info': {
        'type': dict,
        'required': True,
        'subfields': {
            'status': {'type': str, 'required': True},
            'source': {'type': str, 'required': False},
        },
    },
    'smtp_transport': {'type': (dict, type(None)), 'required': True},
    'hosting_summary': {
        'type': dict,
        'required': True,
        'subfields': {
            'hosting': {'type': str, 'required': True},
            'dns_hosting': {'type': str, 'required': True},
            'email_hosting': {'type': str, 'required': True},
        },
    },
    'posture': {
        'type': dict,
        'required': True,
        'subfields': {
            'issues': {'type': (list, type(None)), 'required': True},
            'color': {'type': str, 'required': True},
        },
    },
    'remediation': {
        'type': dict,
        'required': False,
        'subfields': {
            'top_fixes': {'type': (list, type(None)), 'required': True},
            'fix_count': {'type': int, 'required': True},
            'posture_achievable': {'type': str, 'required': True},
            'all_fixes': {'type': (list, type(None)), 'required': False},
        },
    },
    '_schema_version': {'type': int, 'required': False},
    '_tool_version': {'type': str, 'required': False},
}

SCHEMA_ACTIVE_DOMAIN_REQUIRED = {
    'resolver_consensus': {
        'type': dict,
        'subfields': {
            'consensus_reached': {'type': bool, 'required': True},
            'resolvers_queried': {'type': int, 'required': True},
            'checks_performed': {'type': int, 'required': True},
            'discrepancies': {'type': (list, type(None)), 'required': True},
            'per_record_consensus': {'type': dict, 'required': True},
        },
    },
    'ct_subdomains': {
        'type': dict,
        'subfields': {
            'status': {'type': str, 'required': True},
            'subdomains': {'type': list, 'required': True},
            'unique_subdomains': {'type': int, 'required': True},
        },
    },
    'dns_infrastructure': {
        'type': dict,
        'subfields': {
            'provider_name': {'type': str, 'required': True},
            'provider_tier': {'type': str, 'required': True},
            'provider_features': {'type': list, 'required': True},
        },
    },
    'email_security_mgmt': {
        'type': dict,
        'subfields': {
            'actively_managed': {'type': bool, 'required': True},
            'provider_count': {'type': int, 'required': True},
            'providers': {'type': list, 'required': True},
        },
    },
    'mail_posture': {
        'type': dict,
        'subfields': {
            'verdict': {'type': str, 'required': True},
            'badge': {'type': str, 'required': True},
        },
    },
    'has_null_mx': {'type': bool},
    'is_no_mail_domain': {'type': bool},
}

POSTURE_SUBFIELDS_ACTIVE = {
    'state': {'type': str, 'required': True},
    'message': {'type': str, 'required': True},
    'issues': {'type': (list, type(None)), 'required': True},
    'color': {'type': str, 'required': True},
    'configured': {'type': (list, type(None)), 'required': True},
    'absent': {'type': (list, type(None)), 'required': True},
    'monitoring': {'type': (list, type(None)), 'required': True},
    'verdicts': {'type': dict, 'required': True},
}

POSTURE_SUBFIELDS_NONEXISTENT = {
    'score': {'type': (int, float), 'required': True},
    'grade': {'type': str, 'required': True},
    'label': {'type': str, 'required': True},
    'issues': {'type': list, 'required': True},
    'color': {'type': str, 'required': True},
}

VALID_STATUS_VALUES = {'success', 'warning', 'error', 'info', 'n/a', 'timeout', 'unknown', 'partial'}

EMAIL_SECURITY_PROVIDER_REQUIRED_FIELDS = ['name', 'capabilities', 'detected_from']


def get_required_sections():
    return list(REQUIRED_SECTIONS)


def _is_none_allowed(expected_type):
    type_tuple = expected_type if isinstance(expected_type, tuple) else (expected_type,)
    return type(None) in type_tuple


def _check_type(value, expected_type, label):
    if value is None and _is_none_allowed(expected_type):
        return None
    if not isinstance(value, expected_type):
        return f'Wrong type for {label}: expected {expected_type}, got {type(value).__name__}'
    return None


def _validate_key(key, spec, results, errors):
    required = spec.get('required', False)
    expected_type = spec['type']

    if key not in results:
        if required:
            errors.append(f'Missing required key: {key}')
        return

    value = results[key]
    type_error = _check_type(value, expected_type, key)
    if type_error:
        errors.append(type_error)
        return

    if 'subfields' in spec and isinstance(value, dict):
        _validate_subfields(key, spec['subfields'], value, errors)

    if 'required_keys' in spec and isinstance(value, dict):
        for rk in spec['required_keys']:
            if rk not in value:
                errors.append(f'Missing required key {key}.{rk}')


def _validate_subfields(parent_key, subfields, value, errors):
    for subkey, subspec in subfields.items():
        if subkey not in value:
            if subspec.get('required', False):
                errors.append(f'Missing required subfield {parent_key}.{subkey}')
            continue
        type_error = _check_type(value[subkey], subspec['type'], f'{parent_key}.{subkey}')
        if type_error:
            errors.append(type_error)


def validate_analysis_results(results: dict) -> list:
    errors = []

    if not isinstance(results, dict):
        return ['Results must be a dictionary']

    for key, spec in ANALYSIS_SCHEMA.items():
        _validate_key(key, spec, results, errors)

    domain_exists = results.get('domain_exists', True)

    _validate_posture(results, errors)
    _validate_dane(results, errors)
    _validate_remediation(results, errors)

    if domain_exists:
        _validate_active_domain_fields(results, errors)
        _validate_email_security_mgmt(results, errors)

    return errors


def _validate_active_domain_fields(results, errors):
    for key, spec in SCHEMA_ACTIVE_DOMAIN_REQUIRED.items():
        expected_type = spec['type']
        if key not in results:
            errors.append(f'Missing required key for active domain: {key}')
            continue
        value = results[key]
        if value is None:
            errors.append(f'Active domain field {key} is null (should not be)')
            continue
        type_error = _check_type(value, expected_type, key)
        if type_error:
            errors.append(type_error)
            continue
        if 'subfields' in spec and isinstance(value, dict):
            _validate_subfields(key, spec['subfields'], value, errors)


def _validate_dict_fields(container, fields, prefix, errors):
    for field, spec in fields.items():
        if field not in container:
            errors.append(f'Missing {prefix}: {field}')
            continue
        type_error = _check_type(container[field], spec['type'], f'posture.{field}')
        if type_error:
            errors.append(type_error)


def _validate_posture(results, errors):
    posture = results.get('posture')
    if not isinstance(posture, dict):
        return

    domain_exists = results.get('domain_exists', True)
    if not domain_exists:
        _validate_dict_fields(posture, POSTURE_SUBFIELDS_NONEXISTENT, 'posture field for non-existent domain', errors)
        _validate_posture_score_range(posture, errors)
    else:
        _validate_dict_fields(posture, POSTURE_SUBFIELDS_ACTIVE, 'posture field for active domain', errors)


def _validate_posture_score_range(posture, errors):
    if 'score' not in posture:
        return
    score = posture['score']
    if isinstance(score, (int, float)) and not (0 <= score <= 100):
        errors.append(f'Posture score out of range: {score} (expected 0-100)')


def _validate_dane(results, errors):
    dane = results.get('dane_analysis')
    if not isinstance(dane, dict):
        return
    if 'status' not in dane:
        errors.append('Missing dane_analysis.status')
    elif not isinstance(dane['status'], str):
        errors.append(f'Wrong type for dane_analysis.status')
    if 'has_dane' not in dane:
        errors.append('Missing dane_analysis.has_dane')
    elif not isinstance(dane['has_dane'], bool):
        errors.append(f'Wrong type for dane_analysis.has_dane')


def _validate_email_security_mgmt(results, errors):
    esm = results.get('email_security_mgmt')
    if not isinstance(esm, dict):
        return

    if 'actively_managed' not in esm:
        errors.append('Missing email_security_mgmt.actively_managed')
    elif not isinstance(esm['actively_managed'], bool):
        errors.append(f'Wrong type for email_security_mgmt.actively_managed: expected bool, got {type(esm["actively_managed"]).__name__}')

    if 'provider_count' not in esm:
        errors.append('Missing email_security_mgmt.provider_count')
    elif not isinstance(esm['provider_count'], int):
        errors.append(f'Wrong type for email_security_mgmt.provider_count: expected int, got {type(esm["provider_count"]).__name__}')

    if 'providers' not in esm:
        errors.append('Missing email_security_mgmt.providers')
        return
    if not isinstance(esm['providers'], list):
        errors.append(f'Wrong type for email_security_mgmt.providers: expected list, got {type(esm["providers"]).__name__}')
        return

    actively_managed = esm.get('actively_managed', False)
    provider_count = esm.get('provider_count', 0)

    if actively_managed and provider_count == 0:
        errors.append('email_security_mgmt.actively_managed is True but provider_count is 0')
    if actively_managed and len(esm['providers']) == 0:
        errors.append('email_security_mgmt.actively_managed is True but providers list is empty')
    if provider_count != len(esm['providers']):
        errors.append(f'email_security_mgmt.provider_count ({provider_count}) does not match len(providers) ({len(esm["providers"])})')

    for i, provider in enumerate(esm['providers']):
        if not isinstance(provider, dict):
            errors.append(f'email_security_mgmt.providers[{i}] must be a dict')
            continue
        for field in EMAIL_SECURITY_PROVIDER_REQUIRED_FIELDS:
            if field not in provider:
                errors.append(f'Missing email_security_mgmt.providers[{i}].{field}')
        if 'name' in provider and not isinstance(provider['name'], str):
            errors.append(f'Wrong type for email_security_mgmt.providers[{i}].name')
        if 'capabilities' in provider and not isinstance(provider['capabilities'], list):
            errors.append(f'Wrong type for email_security_mgmt.providers[{i}].capabilities')
        if 'detected_from' in provider and not isinstance(provider['detected_from'], list):
            errors.append(f'Wrong type for email_security_mgmt.providers[{i}].detected_from')


VALID_REMEDIATION_SEVERITIES = {'Critical', 'High', 'Medium', 'Low'}
VALID_REMEDIATION_SECTIONS = {'spf', 'dmarc', 'dkim', 'dnssec', 'dane', 'mta_sts', 'tlsrpt', 'bimi', 'caa'}
VALID_REMEDIATION_SECTION_STATUSES = {'ok', 'action_needed', 'not_applicable', 'blocked', 'optional'}

_REMEDIATION_FIX_FIELDS = ('title', 'severity_label', 'severity_color', 'fix', 'rfc', 'rfc_url')


def _validate_remediation_fix(i, fix, errors):
    if not isinstance(fix, dict):
        errors.append(f'remediation.top_fixes[{i}] must be a dict')
        return
    for field in _REMEDIATION_FIX_FIELDS:
        if field not in fix:
            errors.append(f'Missing remediation.top_fixes[{i}].{field}')
    severity_label = fix.get('severity_label')
    if severity_label and severity_label not in VALID_REMEDIATION_SEVERITIES:
        errors.append(f'Invalid severity_label in remediation fix: {severity_label}')


def _validate_remediation_per_section(per_section, errors):
    if not isinstance(per_section, dict):
        return
    for section_key, section_data in per_section.items():
        if section_key not in VALID_REMEDIATION_SECTIONS:
            errors.append(f'Invalid remediation per_section key: {section_key}')
        if not isinstance(section_data, dict):
            continue
        status = section_data.get('status')
        if status and status not in VALID_REMEDIATION_SECTION_STATUSES:
            errors.append(f'Invalid remediation per_section status for {section_key}: {status}')


def _validate_remediation(results, errors):
    rem = results.get('remediation')
    if not isinstance(rem, dict):
        return
    if 'top_fixes' not in rem:
        errors.append('Missing remediation.top_fixes')
        return
    top_fixes = rem['top_fixes']
    if top_fixes is None:
        return
    if not isinstance(top_fixes, list):
        errors.append(f'Wrong type for remediation.top_fixes: expected list, got {type(top_fixes).__name__}')
        return
    for i, fix in enumerate(top_fixes):
        _validate_remediation_fix(i, fix, errors)


VALID_POSTURE_STATES = {'STRONG', 'GOOD', 'MODERATE', 'FAIR', 'WEAK', 'CRITICAL'}
VALID_POSTURE_COLORS = {'success', 'info', 'warning', 'danger', 'secondary'}
VALID_MAIL_VERDICTS = {'Protected', 'Monitoring', 'Partial', 'Minimal', 'No Mail', 'Unprotected', 'Unknown'}
VALID_DMARC_POLICIES = {'none', 'quarantine', 'reject'}
VALID_DNS_INFRA_TIERS = {'enterprise', 'professional', 'standard', 'basic', 'unknown'}


def _check_value_in_set(value, valid_set, label):
    if value and value not in valid_set:
        return f'Invalid {label}: {value}'
    return None


def validate_analysis_deep(results: dict) -> list:
    errors = validate_analysis_results(results)
    if errors:
        return errors

    domain_exists = results.get('domain_exists', True)
    posture = results.get('posture', {})

    if domain_exists:
        err = _check_value_in_set(posture.get('state', ''), VALID_POSTURE_STATES, 'posture state')
        if err:
            errors.append(err)

    err = _check_value_in_set(posture.get('color', ''), VALID_POSTURE_COLORS, 'posture color')
    if err:
        errors.append(err)

    _validate_deep_dmarc(results, errors)
    _validate_deep_spf(results, errors)

    if domain_exists:
        _validate_deep_dns_infrastructure(results, errors)
        _validate_deep_email_security_mgmt(results, errors)

    return errors


def _validate_deep_dmarc(results, errors):
    dmarc = results.get('dmarc_analysis', {})
    if dmarc.get('status') not in ('success', 'warning'):
        return
    policy = dmarc.get('policy')
    if not policy:
        return
    if policy not in VALID_DMARC_POLICIES:
        errors.append(f'Invalid DMARC policy: {policy}')


def _validate_deep_spf(results, errors):
    spf = results.get('spf_analysis', {})
    if spf.get('status') not in ('success', 'warning'):
        return
    if 'lookup_count' not in spf:
        return
    lc = spf['lookup_count']
    if not isinstance(lc, int) or lc < 0:
        errors.append(f'Invalid SPF lookup_count: {lc}')


def _validate_deep_dns_infrastructure(results, errors):
    di = results.get('dns_infrastructure', {})
    if not isinstance(di, dict):
        return
    err = _check_value_in_set(di.get('provider_tier', ''), VALID_DNS_INFRA_TIERS, 'dns_infrastructure.provider_tier')
    if err:
        errors.append(err)


def _validate_deep_email_security_mgmt(results, errors):
    esm = results.get('email_security_mgmt', {})
    if not isinstance(esm, dict):
        return
    for i, provider in enumerate(esm.get('providers', [])):
        if not isinstance(provider, dict):
            continue
        caps = provider.get('capabilities', [])
        if not isinstance(caps, list):
            continue
        valid_caps = {'DMARC', 'SPF', 'DKIM', 'MTA-STS', 'TLS-RPT', 'BIMI',
                      'DMARC reporting', 'DMARC analytics', 'SPF flattening',
                      'email security', 'domain monitoring'}
        for cap in caps:
            if cap not in valid_caps:
                errors.append(f'Unknown capability "{cap}" in email_security_mgmt.providers[{i}]')
        detected = provider.get('detected_from', [])
        if not isinstance(detected, list) or len(detected) == 0:
            errors.append(f'email_security_mgmt.providers[{i}] has empty detected_from')
