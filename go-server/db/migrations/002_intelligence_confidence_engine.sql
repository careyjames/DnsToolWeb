-- Migration 002: Intelligence Confidence Audit Engine (ICAE) tables
-- Applied: 2026-02-18
-- Operator: admin
-- Status: PENDING
--
-- Context: ICAE tracks per-protocol accuracy across two layers:
--   Layer 1 (collection): Did we successfully retrieve raw DNS data?
--   Layer 2 (analysis):   Did we correctly classify and interpret per RFC?
--
-- Maturity progression: development → verified → consistent → gold → master_gold
-- Regression detection: any test failure immediately degrades maturity level.

CREATE TABLE IF NOT EXISTS ice_protocols (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL UNIQUE,
    display_name VARCHAR(50) NOT NULL,
    rfc_refs TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO ice_protocols (protocol, display_name, rfc_refs) VALUES
    ('spf',      'SPF',      '{"RFC 7208","RFC 7489"}'),
    ('dkim',     'DKIM',     '{"RFC 6376","RFC 8463"}'),
    ('dmarc',    'DMARC',    '{"RFC 7489","RFC 9091"}'),
    ('dane',     'DANE/TLSA','{"RFC 6698","RFC 7671","RFC 7672"}'),
    ('dnssec',   'DNSSEC',   '{"RFC 4033","RFC 4034","RFC 4035"}'),
    ('bimi',     'BIMI',     '{"RFC 9495"}'),
    ('mta_sts',  'MTA-STS',  '{"RFC 8461"}'),
    ('tlsrpt',   'TLS-RPT',  '{"RFC 8460"}'),
    ('caa',      'CAA',      '{"RFC 8659"}')
ON CONFLICT (protocol) DO NOTHING;

CREATE TABLE IF NOT EXISTS ice_test_runs (
    id SERIAL PRIMARY KEY,
    app_version VARCHAR(20) NOT NULL,
    git_commit VARCHAR(40) NOT NULL DEFAULT '',
    run_type VARCHAR(20) NOT NULL DEFAULT 'ci',
    total_cases INTEGER NOT NULL DEFAULT 0,
    total_passed INTEGER NOT NULL DEFAULT 0,
    total_failed INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ice_test_runs_created ON ice_test_runs (created_at);
CREATE INDEX IF NOT EXISTS ix_ice_test_runs_version ON ice_test_runs (app_version);

CREATE TABLE IF NOT EXISTS ice_results (
    id SERIAL PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES ice_test_runs(id) ON DELETE CASCADE,
    protocol VARCHAR(20) NOT NULL,
    layer VARCHAR(20) NOT NULL,
    case_id VARCHAR(100) NOT NULL,
    case_name VARCHAR(255) NOT NULL DEFAULT '',
    passed BOOLEAN NOT NULL,
    expected TEXT,
    actual TEXT,
    rfc_section VARCHAR(50),
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT ice_results_layer_check CHECK (layer IN ('collection', 'analysis'))
);

CREATE INDEX IF NOT EXISTS ix_ice_results_run ON ice_results (run_id);
CREATE INDEX IF NOT EXISTS ix_ice_results_protocol ON ice_results (protocol, layer);
CREATE INDEX IF NOT EXISTS ix_ice_results_case ON ice_results (case_id);

CREATE TABLE IF NOT EXISTS ice_maturity (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL,
    layer VARCHAR(20) NOT NULL,
    maturity VARCHAR(20) NOT NULL DEFAULT 'development',
    total_runs INTEGER NOT NULL DEFAULT 0,
    consecutive_passes INTEGER NOT NULL DEFAULT 0,
    first_pass_at TIMESTAMP,
    last_regression_at TIMESTAMP,
    last_evaluated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT ice_maturity_unique UNIQUE (protocol, layer),
    CONSTRAINT ice_maturity_layer_check CHECK (layer IN ('collection', 'analysis')),
    CONSTRAINT ice_maturity_level_check CHECK (maturity IN ('development', 'verified', 'consistent', 'gold', 'master_gold'))
);

INSERT INTO ice_maturity (protocol, layer, maturity) VALUES
    ('spf',      'collection', 'development'),
    ('spf',      'analysis',   'development'),
    ('dkim',     'collection', 'development'),
    ('dkim',     'analysis',   'development'),
    ('dmarc',    'collection', 'development'),
    ('dmarc',    'analysis',   'development'),
    ('dane',     'collection', 'development'),
    ('dane',     'analysis',   'development'),
    ('dnssec',   'collection', 'development'),
    ('dnssec',   'analysis',   'development'),
    ('bimi',     'collection', 'development'),
    ('bimi',     'analysis',   'development'),
    ('mta_sts',  'collection', 'development'),
    ('mta_sts',  'analysis',   'development'),
    ('tlsrpt',   'collection', 'development'),
    ('tlsrpt',   'analysis',   'development'),
    ('caa',      'collection', 'development'),
    ('caa',      'analysis',   'development')
ON CONFLICT (protocol, layer) DO NOTHING;

CREATE TABLE IF NOT EXISTS ice_regressions (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL,
    layer VARCHAR(20) NOT NULL,
    run_id INTEGER NOT NULL REFERENCES ice_test_runs(id) ON DELETE CASCADE,
    previous_maturity VARCHAR(20) NOT NULL,
    new_maturity VARCHAR(20) NOT NULL,
    failed_cases TEXT[] NOT NULL DEFAULT '{}',
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ice_regressions_protocol ON ice_regressions (protocol, layer, created_at);
