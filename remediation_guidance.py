"""Actionable remediation guidance engine for DNS security posture.

Maps analysis verdicts to prioritized, RFC-cited fix recommendations.
Each recommendation includes: what to do, why it matters, the RFC basis,
and a severity/impact score for prioritization.
"""

from typing import Dict, Any, List, Optional


SEVERITY_CRITICAL = 1
SEVERITY_HIGH = 2
SEVERITY_MEDIUM = 3
SEVERITY_LOW = 4

SEVERITY_LABELS = {
    SEVERITY_CRITICAL: 'Critical',
    SEVERITY_HIGH: 'High',
    SEVERITY_MEDIUM: 'Medium',
    SEVERITY_LOW: 'Low',
}

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: 'danger',
    SEVERITY_HIGH: 'warning',
    SEVERITY_MEDIUM: 'info',
    SEVERITY_LOW: 'secondary',
}


def generate_remediation(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate actionable remediation guidance from analysis results.

    Returns:
        {
            'top_fixes': [  # Prioritized list of most impactful fixes
                {
                    'title': str,
                    'section': str,
                    'severity': int,
                    'severity_label': str,
                    'severity_color': str,
                    'fix': str,           # What to do
                    'why': str,           # Why it matters
                    'rfc': str,           # RFC citation
                    'rfc_url': str,       # Link to RFC
                    'dns_record': str,    # Example DNS record to add
                }
            ],
            'per_section': {  # Per-section remediation hints
                'spf': {...},
                'dmarc': {...},
                ...
            },
            'fix_count': int,
            'posture_achievable': str,  # What posture could be achieved
        }
    """
    fixes = []
    per_section = {}
    is_no_mail = results.get('is_no_mail_domain', False)

    _check_spf(results, fixes, per_section, is_no_mail)
    _check_dmarc(results, fixes, per_section, is_no_mail)
    _check_dkim(results, fixes, per_section, is_no_mail)
    _check_dnssec(results, fixes, per_section)
    _check_dane(results, fixes, per_section, is_no_mail)
    _check_mta_sts(results, fixes, per_section, is_no_mail)
    _check_tlsrpt(results, fixes, per_section, is_no_mail)
    _check_bimi(results, fixes, per_section, is_no_mail)
    _check_caa(results, fixes, per_section)

    fixes.sort(key=lambda f: (f['severity'], f['title']))

    top_fixes = fixes[:3]

    posture_achievable = _estimate_achievable_posture(results, fixes)

    return {
        'top_fixes': top_fixes,
        'per_section': per_section,
        'fix_count': len(fixes),
        'posture_achievable': posture_achievable,
    }


def _make_fix(title: str, section: str, severity: int, fix: str, why: str,
              rfc: str, rfc_url: str, dns_record: str = '') -> Dict[str, Any]:
    return {
        'title': title,
        'section': section,
        'severity': severity,
        'severity_label': SEVERITY_LABELS[severity],
        'severity_color': SEVERITY_COLORS[severity],
        'fix': fix,
        'why': why,
        'rfc': rfc,
        'rfc_url': rfc_url,
        'dns_record': dns_record,
    }


def _check_spf(results, fixes, per_section, is_no_mail):
    spf = results.get('spf_analysis', {})
    status = spf.get('status', '')
    section_fixes = []

    if status == 'error' or status == '':
        if is_no_mail:
            f = _make_fix(
                'Add SPF record to block spoofing',
                'spf', SEVERITY_HIGH,
                'Publish an SPF record that rejects all senders since this domain does not send email.',
                'Without SPF, attackers can send email appearing to come from your domain.',
                'RFC 7208', 'https://datatracker.ietf.org/doc/html/rfc7208',
                'v=spf1 -all'
            )
        else:
            f = _make_fix(
                'Add SPF record',
                'spf', SEVERITY_CRITICAL,
                'Publish an SPF record listing your authorized mail servers. '
                'Include your email provider (e.g., include:_spf.google.com for Google Workspace).',
                'SPF tells receiving servers which IP addresses are allowed to send email for your domain. '
                'Without it, anyone can send email pretending to be you.',
                'RFC 7208', 'https://datatracker.ietf.org/doc/html/rfc7208',
                'v=spf1 include:_spf.google.com ~all'
            )
        fixes.append(f)
        section_fixes.append(f)
    elif spf.get('permissiveness') == 'DANGEROUS':
        f = _make_fix(
            'Fix dangerously permissive SPF',
            'spf', SEVERITY_CRITICAL,
            'Remove +all from your SPF record. Use ~all or -all instead to restrict who can send as your domain.',
            'SPF with +all allows any server in the world to send email as your domain — it provides zero protection.',
            'RFC 7208 §5.1', 'https://datatracker.ietf.org/doc/html/rfc7208#section-5.1',
            'v=spf1 include:your-provider ~all'
        )
        fixes.append(f)
        section_fixes.append(f)
    elif spf.get('permissiveness') == 'NEUTRAL':
        f = _make_fix(
            'Strengthen SPF enforcement',
            'spf', SEVERITY_HIGH,
            'Change your SPF all-mechanism from ?all (neutral) to ~all (softfail) or -all (hardfail).',
            'Neutral (?all) tells receivers to accept email regardless of SPF check results.',
            'RFC 7208 §5.2', 'https://datatracker.ietf.org/doc/html/rfc7208#section-5.2',
        )
        fixes.append(f)
        section_fixes.append(f)

    lookup_count = spf.get('lookup_count', 0)
    if lookup_count and lookup_count > 10:
        f = _make_fix(
            'Reduce SPF DNS lookups',
            'spf', SEVERITY_MEDIUM,
            f'Your SPF record uses {lookup_count} DNS lookups (limit is 10). '
            'Consolidate include mechanisms or use SPF flattening to stay within the limit.',
            'Exceeding 10 DNS lookups causes SPF to permanently fail (permerror), '
            'meaning receivers treat it as if you have no SPF at all.',
            'RFC 7208 §4.6.4', 'https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4',
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['spf'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['spf'] = {'status': 'ok', 'fixes': []}


def _check_dmarc(results, fixes, per_section, _is_no_mail):
    dmarc = results.get('dmarc_analysis', {})
    status = dmarc.get('status', '')
    policy = (dmarc.get('policy') or '').lower()
    section_fixes = []

    if status == 'error' or (status not in ('success', 'warning', 'info') and not policy):
        f = _make_fix(
            'Add DMARC policy',
            'dmarc', SEVERITY_CRITICAL,
            'Publish a DMARC record. Start with p=none and a reporting address to monitor authentication results, '
            'then escalate to p=quarantine and finally p=reject.',
            'DMARC is the master policy that tells receivers what to do with emails that fail SPF and DKIM checks. '
            'Without it, spoofed emails reach inboxes even if SPF is configured.',
            'RFC 7489', 'https://datatracker.ietf.org/doc/html/rfc7489',
            'v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com'
        )
        fixes.append(f)
        section_fixes.append(f)
    elif policy == 'none':
        f = _make_fix(
            'Escalate DMARC from monitoring to enforcement',
            'dmarc', SEVERITY_HIGH,
            'Change your DMARC policy from p=none to p=quarantine (then p=reject). '
            'Review your DMARC aggregate reports first to ensure legitimate senders pass authentication.',
            'DMARC p=none only monitors — spoofed emails are still delivered to inboxes. '
            'Enforcement (quarantine/reject) is required to actually block spoofing.',
            'RFC 7489 §6.3', 'https://datatracker.ietf.org/doc/html/rfc7489#section-6.3',
            'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com'
        )
        fixes.append(f)
        section_fixes.append(f)
    elif policy == 'quarantine':
        f = _make_fix(
            'Upgrade DMARC to reject policy',
            'dmarc', SEVERITY_MEDIUM,
            'Upgrade your DMARC policy from p=quarantine to p=reject for maximum protection. '
            'Quarantine flags spoofed messages as spam; reject blocks them entirely.',
            'DMARC p=reject is the strongest enforcement level — receiving servers will refuse delivery of spoofed messages.',
            'RFC 7489 §6.3', 'https://datatracker.ietf.org/doc/html/rfc7489#section-6.3',
            'v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com'
        )
        fixes.append(f)
        section_fixes.append(f)

    if not dmarc.get('rua') and policy:
        f = _make_fix(
            'Add DMARC aggregate reporting',
            'dmarc', SEVERITY_MEDIUM,
            'Add a rua= tag to your DMARC record to receive aggregate reports about authentication results.',
            'Without reporting, you cannot see who is sending email as your domain or whether legitimate mail is failing authentication.',
            'RFC 7489 §7.1', 'https://datatracker.ietf.org/doc/html/rfc7489#section-7.1',
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['dmarc'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['dmarc'] = {'status': 'ok', 'fixes': []}


def _check_dkim(results, fixes, per_section, is_no_mail):
    dkim = results.get('dkim_analysis', {})
    status = dkim.get('status', '')
    section_fixes = []

    if is_no_mail:
        per_section['dkim'] = {'status': 'not_applicable', 'fixes': []}
        return

    if status in ('error', '') and not dkim.get('selectors'):
        f = _make_fix(
            'Configure DKIM signing',
            'dkim', SEVERITY_HIGH,
            'Enable DKIM in your email provider settings. This publishes a public key in DNS and signs outgoing messages. '
            'Most providers (Google Workspace, Microsoft 365, etc.) have a DKIM setup wizard.',
            'DKIM cryptographically signs your emails so receivers can verify they have not been tampered with. '
            'It is essential for DMARC alignment.',
            'RFC 6376', 'https://datatracker.ietf.org/doc/html/rfc6376',
        )
        fixes.append(f)
        section_fixes.append(f)

    key_issues = dkim.get('key_issues', [])
    if any('1024' in i for i in key_issues):
        f = _make_fix(
            'Upgrade DKIM keys to 2048-bit',
            'dkim', SEVERITY_MEDIUM,
            'Rotate your DKIM keys to use 2048-bit RSA. Most email providers support this in their admin console.',
            '1024-bit RSA keys are considered weak by modern standards and could potentially be factored.',
            'RFC 6376 §3.3.3', 'https://datatracker.ietf.org/doc/html/rfc6376#section-3.3.3',
        )
        fixes.append(f)
        section_fixes.append(f)

    if dkim.get('third_party_only'):
        primary = dkim.get('primary_provider', 'primary mail platform')
        f = _make_fix(
            f'Enable DKIM for {primary}',
            'dkim', SEVERITY_MEDIUM,
            f'DKIM is only configured for third-party services, not your primary email platform ({primary}). '
            f'Enable DKIM signing in {primary} settings to cover all outbound mail.',
            'Messages sent from your primary platform lack DKIM signatures, '
            'which may cause DMARC alignment failures.',
            'RFC 6376 §2.1', 'https://datatracker.ietf.org/doc/html/rfc6376#section-2.1',
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['dkim'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['dkim'] = {'status': 'ok', 'fixes': []}


def _check_dnssec(results, fixes, per_section):
    dnssec = results.get('dnssec_analysis', {})
    status = dnssec.get('status', '')
    chain = dnssec.get('chain_of_trust', 'none')
    section_fixes = []

    if chain == 'broken':
        f = _make_fix(
            'Fix broken DNSSEC chain',
            'dnssec', SEVERITY_CRITICAL,
            'Your domain has DNSSEC records but the chain of trust is broken — likely a missing DS record at your registrar. '
            'Contact your registrar to add the correct DS record, or if DNSSEC was disabled, remove stale DS records.',
            'A broken DNSSEC chain causes validation failures for DNSSEC-aware resolvers, '
            'potentially making your domain unreachable for some users.',
            'RFC 4035 §5', 'https://datatracker.ietf.org/doc/html/rfc4035#section-5',
        )
        fixes.append(f)
        section_fixes.append(f)
    elif status != 'success':
        f = _make_fix(
            'Enable DNSSEC',
            'dnssec', SEVERITY_LOW,
            'Enable DNSSEC at your DNS provider and add the DS record at your registrar. '
            'Many DNS providers (Cloudflare, Route 53, etc.) offer one-click DNSSEC activation.',
            'DNSSEC cryptographically signs DNS responses, preventing attackers from forging DNS answers. '
            'Many large operators choose not to deploy it — this is a design choice, not a vulnerability.',
            'RFC 4035', 'https://datatracker.ietf.org/doc/html/rfc4035',
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['dnssec'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['dnssec'] = {'status': 'ok', 'fixes': []}


def _check_dane(results, fixes, per_section, is_no_mail):
    dane = results.get('dane_analysis', {})
    dnssec = results.get('dnssec_analysis', {})
    has_dnssec = dnssec.get('status') == 'success'
    section_fixes = []

    if is_no_mail:
        per_section['dane'] = {'status': 'not_applicable', 'fixes': []}
        return

    if dane.get('has_dane') and not has_dnssec:
        f = _make_fix(
            'Validate DANE with DNSSEC',
            'dane', SEVERITY_HIGH,
            'Your domain has TLSA records but DNSSEC is not validated. '
            'DANE requires DNSSEC — without it, TLSA records can be spoofed, negating DANE\'s security.',
            'DANE without DNSSEC is insecure. An attacker who can forge DNS responses can also forge TLSA records.',
            'RFC 7672 §1.3', 'https://datatracker.ietf.org/doc/html/rfc7672#section-1.3',
        )
        fixes.append(f)
        section_fixes.append(f)
    elif not dane.get('has_dane') and has_dnssec and dane.get('dane_deployable', True):
        f = _make_fix(
            'Deploy DANE/TLSA for mail transport',
            'dane', SEVERITY_LOW,
            'Since DNSSEC is already active, you can add TLSA records for your MX hosts to enable DANE. '
            'This cryptographically pins TLS certificates for mail delivery.',
            'DANE provides the strongest form of transport security for email — '
            'it prevents man-in-the-middle attacks on mail delivery without relying on certificate authorities.',
            'RFC 6698', 'https://datatracker.ietf.org/doc/html/rfc6698',
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['dane'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif dane.get('has_dane') and has_dnssec:
        per_section['dane'] = {'status': 'ok', 'fixes': []}


def _check_mta_sts(results, fixes, per_section, is_no_mail):
    mta_sts = results.get('mta_sts_analysis', {})
    status = mta_sts.get('status', '')
    section_fixes = []

    if is_no_mail:
        per_section['mta_sts'] = {'status': 'not_applicable', 'fixes': []}
        return

    if status != 'success':
        dane = results.get('dane_analysis', {})
        if dane.get('has_dane') and results.get('dnssec_analysis', {}).get('status') == 'success':
            per_section['mta_sts'] = {'status': 'optional', 'fixes': []}
            return

        f = _make_fix(
            'Deploy MTA-STS policy',
            'mta_sts', SEVERITY_MEDIUM,
            'Publish an MTA-STS DNS record and host a policy file at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt. '
            'This tells senders to require TLS when delivering mail to your domain.',
            'Without MTA-STS (or DANE), email in transit can be intercepted via TLS downgrade attacks. '
            'MTA-STS is the HTTPS-based alternative to DANE and does not require DNSSEC.',
            'RFC 8461', 'https://datatracker.ietf.org/doc/html/rfc8461',
            '_mta-sts.yourdomain.com TXT "v=STSv1; id=20240101"'
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['mta_sts'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['mta_sts'] = {'status': 'ok', 'fixes': []}


def _check_tlsrpt(results, fixes, per_section, is_no_mail):
    tlsrpt = results.get('tlsrpt_analysis', {})
    status = tlsrpt.get('status', '')
    section_fixes = []

    if is_no_mail:
        per_section['tlsrpt'] = {'status': 'not_applicable', 'fixes': []}
        return

    if status != 'success':
        f = _make_fix(
            'Add TLS-RPT reporting',
            'tlsrpt', SEVERITY_LOW,
            'Publish a TLS-RPT DNS record to receive reports about TLS delivery failures to your domain.',
            'TLS-RPT lets you know when senders cannot establish a secure connection to deliver email to you. '
            'It complements MTA-STS and DANE by providing visibility into delivery problems.',
            'RFC 8460', 'https://datatracker.ietf.org/doc/html/rfc8460',
            '_smtp._tls.yourdomain.com TXT "v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com"'
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['tlsrpt'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['tlsrpt'] = {'status': 'ok', 'fixes': []}


def _check_bimi(results, fixes, per_section, is_no_mail):
    bimi = results.get('bimi_analysis', {})
    status = bimi.get('status', '')
    section_fixes = []

    if is_no_mail:
        per_section['bimi'] = {'status': 'not_applicable', 'fixes': []}
        return

    dmarc = results.get('dmarc_analysis', {})
    dmarc_policy = (dmarc.get('policy') or '').lower()

    if status != 'success':
        if dmarc_policy not in ('quarantine', 'reject'):
            per_section['bimi'] = {'status': 'blocked', 'fixes': [],
                                   'note': 'BIMI requires DMARC p=quarantine or p=reject first'}
            return

        f = _make_fix(
            'Configure BIMI brand logo',
            'bimi', SEVERITY_LOW,
            'Publish a BIMI DNS record pointing to your brand logo (SVG Tiny PS format). '
            'For full support in Gmail, you will also need a Verified Mark Certificate (VMC).',
            'BIMI displays your brand logo next to emails in supported clients (Gmail, Apple Mail, Yahoo), '
            'increasing brand trust and email engagement.',
            'RFC 9495', 'https://datatracker.ietf.org/doc/html/rfc9495',
            'default._bimi.yourdomain.com TXT "v=BIMI1; l=https://yourdomain.com/logo.svg"'
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['bimi'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['bimi'] = {'status': 'ok', 'fixes': []}


def _check_caa(results, fixes, per_section):
    caa = results.get('caa_analysis', {})
    status = caa.get('status', '')
    section_fixes = []

    if status != 'success':
        f = _make_fix(
            'Add CAA records',
            'caa', SEVERITY_LOW,
            'Publish CAA DNS records to restrict which Certificate Authorities can issue TLS certificates for your domain. '
            'Specify your preferred CA (e.g., letsencrypt.org, digicert.com).',
            'Without CAA, any of the hundreds of CAs worldwide can issue a certificate for your domain. '
            'CAA limits this to only your authorized CAs.',
            'RFC 8659', 'https://datatracker.ietf.org/doc/html/rfc8659',
            'yourdomain.com CAA 0 issue "letsencrypt.org"'
        )
        fixes.append(f)
        section_fixes.append(f)

    if section_fixes:
        per_section['caa'] = {'status': 'action_needed', 'fixes': section_fixes}
    elif status == 'success':
        per_section['caa'] = {'status': 'ok', 'fixes': []}


def _estimate_achievable_posture(results: Dict[str, Any], fixes: List[Dict]) -> str:
    """Estimate what posture state the domain could achieve if all fixes are applied."""
    has_critical = any(f['severity'] == SEVERITY_CRITICAL for f in fixes)
    has_high = any(f['severity'] == SEVERITY_HIGH for f in fixes)
    has_only_low = all(f['severity'] >= SEVERITY_LOW for f in fixes)

    dnssec_ok = results.get('dnssec_analysis', {}).get('status') == 'success'
    dnssec_fix_present = any(f['section'] == 'dnssec' for f in fixes)

    if not fixes:
        if dnssec_ok:
            return 'SECURE'
        return 'STRONG'

    if has_only_low and not has_critical and not has_high:
        if dnssec_ok or dnssec_fix_present:
            return 'SECURE'
        return 'STRONG'

    if not has_critical and dnssec_ok:
        return 'SECURE'

    if not has_critical:
        return 'STRONG'

    return 'PARTIAL'
