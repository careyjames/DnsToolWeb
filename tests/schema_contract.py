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
    '_schema_version': {'type': int, 'required': True},
    '_tool_version': {'type': str, 'required': True},
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


def validate_analysis_results(results: dict) -> list:
    errors = []

    if not isinstance(results, dict):
        return ['Results must be a dictionary']

    for key, spec in ANALYSIS_SCHEMA.items():
        required = spec.get('required', False)
        expected_type = spec['type']

        if key not in results:
            if required:
                errors.append(f'Missing required key: {key}')
            continue

        value = results[key]

        if value is not None or type(None) not in (expected_type if isinstance(expected_type, tuple) else (expected_type,)):
            if not isinstance(value, expected_type):
                errors.append(f'Wrong type for {key}: expected {expected_type}, got {type(value).__name__}')
                continue

        if 'subfields' in spec and isinstance(value, dict):
            for subkey, subspec in spec['subfields'].items():
                if subkey not in value:
                    if subspec.get('required', False):
                        errors.append(f'Missing required subfield {key}.{subkey}')
                    continue
                subval = value[subkey]
                sub_expected = subspec['type']
                if subval is not None or type(None) not in (sub_expected if isinstance(sub_expected, tuple) else (sub_expected,)):
                    if not isinstance(subval, sub_expected):
                        errors.append(f'Wrong type for {key}.{subkey}: expected {sub_expected}, got {type(subval).__name__}')

    _validate_posture(results, errors)
    _validate_dane(results, errors)
    _validate_mail_posture(results, errors)
    _validate_hosting_summary(results, errors)

    return errors


def _validate_posture(results, errors):
    posture = results.get('posture')
    if not isinstance(posture, dict):
        return

    domain_exists = results.get('domain_exists', True)

    if not domain_exists:
        for field, spec in POSTURE_SUBFIELDS_NONEXISTENT.items():
            if field not in posture:
                errors.append(f'Missing posture field for non-existent domain: {field}')
            elif not isinstance(posture[field], spec['type']):
                errors.append(f'Wrong type for posture.{field}: expected {spec["type"]}, got {type(posture[field]).__name__}')
        if 'score' in posture:
            score = posture['score']
            if isinstance(score, (int, float)) and not (0 <= score <= 100):
                errors.append(f'Posture score out of range: {score} (expected 0-100)')
    else:
        for field, spec in POSTURE_SUBFIELDS_ACTIVE.items():
            if field not in posture:
                errors.append(f'Missing posture field for active domain: {field}')
            elif not isinstance(posture[field], spec['type']):
                errors.append(f'Wrong type for posture.{field}: expected {spec["type"]}, got {type(posture[field]).__name__}')


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


VALID_POSTURE_STATES = {'STRONG', 'GOOD', 'MODERATE', 'WEAK', 'CRITICAL'}
VALID_POSTURE_COLORS = {'success', 'info', 'warning', 'danger', 'secondary'}
VALID_MAIL_CLASSIFICATIONS = {
    'email_enabled', 'email_minimal', 'email_passive',
    'no_mail_verified', 'no_mail_partial', 'no_mail_intent',
    'unknown',
}
VALID_DMARC_POLICIES = {'none', 'quarantine', 'reject'}


def validate_analysis_deep(results: dict) -> list:
    """Deep validation — checks field value constraints beyond types.
    Used for Go migration parity verification."""
    errors = validate_analysis_results(results)
    if errors:
        return errors

    domain_exists = results.get('domain_exists', True)

    posture = results.get('posture', {})
    if domain_exists:
        state = posture.get('state', '')
        if state and state not in VALID_POSTURE_STATES:
            errors.append(f'Invalid posture state: {state}')

    color = posture.get('color', '')
    if color and color not in VALID_POSTURE_COLORS:
        errors.append(f'Invalid posture color: {color}')

    mp = results.get('mail_posture', {})
    classification = mp.get('classification', '')
    if classification and classification not in VALID_MAIL_CLASSIFICATIONS:
        errors.append(f'Invalid mail_posture classification: {classification}')

    dmarc = results.get('dmarc_analysis', {})
    if dmarc.get('status') in ('success', 'warning') and dmarc.get('policy'):
        policy = dmarc['policy']
        if policy not in VALID_DMARC_POLICIES:
            errors.append(f'Invalid DMARC policy: {policy}')

    spf = results.get('spf_analysis', {})
    if spf.get('status') in ('success', 'warning'):
        if 'lookup_count' in spf:
            lc = spf['lookup_count']
            if not isinstance(lc, int) or lc < 0:
                errors.append(f'Invalid SPF lookup_count: {lc}')

    return errors
