#!/usr/bin/env python3
"""
Golden Fixture Capture — Go Server Edition

Captures analysis results from the running Go server for use as golden
fixtures in regression testing. Replaces the Python-only capture script.

Usage:
    python3 tests/golden_fixture_capture_go.py

Prerequisites:
    - Go server must be running on localhost:5000
"""
import sys
import os
import json
import time
import re
import requests
from datetime import datetime, timezone

CURATED_DOMAINS = [
    "google.com",
    "example.com",
    "thisdoesnotexist-xz9q.com",
    "whitehouse.gov",
    "cloudflare.com",
]

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'golden_fixtures')
BASE_URL = "http://localhost:5000"


def sanitize_domain(domain):
    return domain.replace('.', '_').replace('/', '_').replace(':', '_')


def get_csrf_token_and_cookies():
    session = requests.Session()
    resp = session.get(BASE_URL + "/")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
    if not match:
        print("ERROR: Could not extract CSRF token from homepage")
        sys.exit(1)
    return match.group(1), session


def run_analysis(domain, csrf_token, session):
    print(f"  Analyzing {domain}...")
    resp = session.post(
        BASE_URL + "/analyze",
        data={"domain": domain, "csrf_token": csrf_token},
        allow_redirects=True,
        timeout=120,
    )
    if resp.status_code != 200:
        print(f"  ERROR: HTTP {resp.status_code} for {domain}")
        return None

    match = re.search(r'/analysis/(\d+)/view', resp.url)
    if not match:
        match = re.search(r'/analysis/(\d+)/view', resp.text)
    if not match:
        print(f"  ERROR: Could not find analysis ID in response for {domain}")
        return None

    analysis_id = match.group(1)
    print(f"  Analysis ID: {analysis_id}")
    return analysis_id


def fetch_analysis_json(analysis_id, session):
    resp = session.get(f"{BASE_URL}/api/analysis/{analysis_id}", timeout=30)
    if resp.status_code != 200:
        print(f"  ERROR: Could not fetch API results for analysis {analysis_id}")
        return None
    api_data = resp.json()
    full_results = api_data.get('full_results')
    if not full_results or not isinstance(full_results, dict):
        print(f"  ERROR: No full_results in API response for analysis {analysis_id}")
        return None
    ct_subs = api_data.get('ct_subdomains')
    if ct_subs and isinstance(ct_subs, dict):
        full_results['ct_subdomains'] = ct_subs
    return full_results


def save_fixture(domain, data, output_dir):
    data['_captured_at'] = datetime.now(timezone.utc).isoformat()
    data['_captured_version'] = 'go-server'
    data['_domain'] = domain
    data['_schema_version'] = 2
    data['_tool_version'] = 'go-server'

    filename = f"{sanitize_domain(domain)}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)

    print(f"  Saved: {filepath}")


def capture_all():
    os.makedirs(FIXTURES_DIR, exist_ok=True)

    print("Getting CSRF token...")
    csrf_token, session = get_csrf_token_and_cookies()
    print(f"  Token: {csrf_token[:20]}...")

    captured = []
    for domain in CURATED_DOMAINS:
        print(f"\n--- {domain} ---")
        try:
            analysis_id = run_analysis(domain, csrf_token, session)
            if not analysis_id:
                continue

            data = fetch_analysis_json(analysis_id, session)
            if not data:
                continue

            save_fixture(domain, data, FIXTURES_DIR)
            captured.append(domain)
            time.sleep(2)
        except Exception as e:
            print(f"  ERROR: {e}")

    manifest = {
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'tool_version': 'go-server',
        'domains': captured,
        'total': len(captured),
    }

    manifest_path = os.path.join(FIXTURES_DIR, 'manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\nManifest saved: {manifest_path}")
    print(f"Captured {len(captured)}/{len(CURATED_DOMAINS)} domains")


if __name__ == '__main__':
    capture_all()
