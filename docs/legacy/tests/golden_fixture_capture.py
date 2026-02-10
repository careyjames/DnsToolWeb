#!/usr/bin/env python3
import sys
import os
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_analyzer import DNSAnalyzer

CURATED_DOMAINS = [
    "google.com",
    "example.com",
    "thisdoesnotexist-xz9q.com",
    "whitehouse.gov",
    "cloudflare.com",
]

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'golden_fixtures')

try:
    from app import APP_VERSION
except ImportError:
    APP_VERSION = "unknown"


def sanitize_domain(domain):
    return domain.replace('.', '_').replace('/', '_').replace(':', '_')


def capture_golden_fixture(domain, output_dir=None):
    if output_dir is None:
        output_dir = FIXTURES_DIR

    os.makedirs(output_dir, exist_ok=True)

    analyzer = DNSAnalyzer()
    print(f"Analyzing {domain}...")
    results = analyzer.analyze_domain(domain)

    results['_captured_at'] = datetime.now(timezone.utc).isoformat()
    results['_captured_version'] = APP_VERSION
    results['_domain'] = domain
    results['_schema_version'] = 2
    results['_tool_version'] = APP_VERSION

    filename = f"{sanitize_domain(domain)}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"  Saved: {filepath}")
    return results


def capture_all(output_dir=None):
    if output_dir is None:
        output_dir = FIXTURES_DIR

    os.makedirs(output_dir, exist_ok=True)

    captured = []
    for domain in CURATED_DOMAINS:
        try:
            capture_golden_fixture(domain, output_dir)
            captured.append(domain)
        except Exception as e:
            print(f"  ERROR capturing {domain}: {e}")

    manifest = {
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'tool_version': APP_VERSION,
        'domains': captured,
        'total': len(captured),
    }

    manifest_path = os.path.join(output_dir, 'manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\nManifest saved: {manifest_path}")
    print(f"Captured {len(captured)}/{len(CURATED_DOMAINS)} domains")

    return manifest


if __name__ == '__main__':
    capture_all()
