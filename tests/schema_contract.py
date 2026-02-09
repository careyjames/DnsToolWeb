import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REQUIRED_SECTIONS = [
    'basic_records', 'spf_analysis', 'dmarc_analysis',
    'dkim_analysis', 'registrar_info', 'posture',
    'dane_analysis', 'mta_sts_analysis', 'tlsrpt_analysis',
    'bimi_analysis', 'caa_analysis', 'dnssec_analysis',
]

ANALYSIS_SCHEMA = {
    'domain_exists': {'type': bool, 'required': True},
    'domain_status': {'type': str, 'required': True},
    'domain_status_message': {'type': (str, type(None)), 'required': True},
    'section_status': {'type': dict, 'required': True},
    'basic_records': {
        'type': dict,
        'required': True,
    },
    'authoritative_records': {'type': dict, 'required': True},
    'auth_query_status': {'type': dict, 'required': True},
    'resolver_ttl': {'type': dict, 'required': True},
    'auth_ttl': {'type': dict, 'required': True},
    'propagation_status': {'type': dict, 'required': True},
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
            'tlsa_records': {'type': list, 'required': True},
            'issues': {'type': list, 'required': True},
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
    },
    'registrar_info': {
        'type': dict,
        'required': True,
    },
    'resolver_consensus': {'type': dict, 'required': True},
    'ct_subdomains': {'type': dict, 'required': True},
    'smtp_transport': {'type': (dict, type(None)), 'required': True},
    '_data_freshness': {'type': dict, 'required': True},
    'has_null_mx': {'type': bool, 'required': True},
    'mail_posture': {
        'type': dict,
        'required': True,
        'subfields': {
            'classification': {'type': str, 'required': True},
        },
    },
    'is_no_mail_domain': {'type': bool, 'required': True},
    'hosting_summary': {
        'type': dict,
        'required': True,
        'subfields': {
            'hosting': {'type': str, 'required': True},
            'dns_hosting': {'type': str, 'required': True},
            'email_hosting': {'type': str, 'required': True},
        },
    },
    'dns_infrastructure': {'type': dict, 'required': True},
    'email_security_mgmt': {'type': dict, 'required': True},
    'posture': {
        'type': dict,
        'required': True,
        'subfields': {
            'issues': {'type': list, 'required': True},
            'color': {'type': str, 'required': True},
        },
    },
    'remediation': {
        'type': dict,
        'required': False,
        'subfields': {
            'top_fixes': {'type': list, 'required': True},
            'per_section': {'type': dict, 'required': True},
            'fix_count': {'type': int, 'required': True},
            'posture_achievable': {'type': str, 'required': True},
        },
    },
    '_schema_version': {'type': int, 'required': False},
    '_tool_version': {'type': str, 'required': False},
}

POSTURE_SUBFIELDS_ACTIVE = {
    'state': {'type': str, 'required': True},
    'message': {'type': str, 'required': True},
    'issues': {'type': list, 'required': True},
    'color': {'type': str, 'required': True},
    'configured': {'type': list, 'required': True},
    'absent': {'type': list, 'required': True},
    'monitoring': {'type': list, 'required': True},
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

    _validate_posture(results, errors)
    _validate_dane(results, errors)
    _validate_mail_posture(results, errors)
    _validate_hosting_summary(results, errors)
    _validate_remediation(results, errors)

    return errors


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
    required_fields = {'status': str, 'has_dane': bool, 'tlsa_records': list, 'issues': list}
    for field, expected_type in required_fields.items():
        if field not in dane:
            errors.append(f'Missing dane_analysis.{field}')
        elif not isinstance(dane[field], expected_type):
            errors.append(f'Wrong type for dane_analysis.{field}: expected {expected_type.__name__}, got {type(dane[field]).__name__}')


def _validate_mail_posture(results, errors):
    mp = results.get('mail_posture')
    if not isinstance(mp, dict):
        return
    if 'classification' not in mp:
        errors.append('Missing mail_posture.classification')
    elif not isinstance(mp['classification'], str):
        errors.append(f'Wrong type for mail_posture.classification: expected str, got {type(mp["classification"]).__name__}')


def _validate_hosting_summary(results, errors):
    hs = results.get('hosting_summary')
    if not isinstance(hs, dict):
        return
    for field in ('hosting', 'dns_hosting', 'email_hosting'):
        if field not in hs:
            errors.append(f'Missing hosting_summary.{field}')
        elif not isinstance(hs[field], str):
            errors.append(f'Wrong type for hosting_summary.{field}: expected str, got {type(hs[field]).__name__}')


VALID_REMEDIATION_SEVERITIES = {'Critical', 'High', 'Medium', 'Low'}
VALID_REMEDIATION_SECTIONS = {'spf', 'dmarc', 'dkim', 'dnssec', 'dane', 'mta_sts', 'tlsrpt', 'bimi', 'caa'}
VALID_REMEDIATION_SECTION_STATUSES = {'ok', 'action_needed', 'not_applicable', 'blocked', 'optional'}

_REMEDIATION_FIX_FIELDS = ('title', 'section', 'severity', 'severity_label', 'severity_color', 'fix', 'why', 'rfc', 'rfc_url')


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
    section = fix.get('section')
    if section and section not in VALID_REMEDIATION_SECTIONS:
        errors.append(f'Invalid section in remediation fix: {section}')


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
    if not isinstance(rem['top_fixes'], list):
        errors.append(f'Wrong type for remediation.top_fixes: expected list, got {type(rem["top_fixes"]).__name__}')
        return
    for i, fix in enumerate(rem['top_fixes']):
        _validate_remediation_fix(i, fix, errors)
    _validate_remediation_per_section(rem.get('per_section', {}), errors)


VALID_POSTURE_STATES = {'STRONG', 'GOOD', 'MODERATE', 'WEAK', 'CRITICAL'}
VALID_POSTURE_COLORS = {'success', 'info', 'warning', 'danger', 'secondary'}
VALID_MAIL_CLASSIFICATIONS = {
    'email_enabled', 'email_minimal', 'email_passive',
    'no_mail_verified', 'no_mail_partial', 'no_mail_intent',
    'unknown',
}
VALID_DMARC_POLICIES = {'none', 'quarantine', 'reject'}


def _check_value_in_set(value, valid_set, label):
    if value and value not in valid_set:
        return f'Invalid {label}: {value}'
    return None


def validate_analysis_deep(results: dict) -> list:
    """Deep validation — checks field value constraints beyond types.
    Used for Go migration parity verification."""
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

    mp = results.get('mail_posture', {})
    err = _check_value_in_set(mp.get('classification', ''), VALID_MAIL_CLASSIFICATIONS, 'mail_posture classification')
    if err:
        errors.append(err)

    _validate_deep_dmarc(results, errors)
    _validate_deep_spf(results, errors)

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
