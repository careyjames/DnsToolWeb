CREATE TABLE domain_analyses (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    ascii_domain VARCHAR(255) NOT NULL,
    basic_records JSON,
    authoritative_records JSON,
    spf_status VARCHAR(20),
    spf_records JSON,
    dmarc_status VARCHAR(20),
    dmarc_policy VARCHAR(20),
    dmarc_records JSON,
    dkim_status VARCHAR(20),
    dkim_selectors JSON,
    registrar_name VARCHAR(255),
    registrar_source VARCHAR(20),
    analysis_success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    analysis_duration DOUBLE PRECISION,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP,
    country_code VARCHAR(10),
    country_name VARCHAR(100),
    ct_subdomains JSON,
    full_results JSON NOT NULL,
    posture_hash VARCHAR(64),
    private BOOLEAN NOT NULL DEFAULT FALSE,
    has_user_selectors BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX ix_domain_analyses_domain ON domain_analyses (domain);
CREATE INDEX ix_domain_analyses_ascii_domain ON domain_analyses (ascii_domain);
CREATE INDEX ix_domain_analyses_created_at ON domain_analyses (created_at);
CREATE INDEX ix_domain_analyses_success_results ON domain_analyses (analysis_success, created_at);

CREATE TABLE analysis_stats (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    total_analyses INTEGER DEFAULT 0,
    successful_analyses INTEGER DEFAULT 0,
    failed_analyses INTEGER DEFAULT 0,
    unique_domains INTEGER DEFAULT 0,
    avg_analysis_time DOUBLE PRECISION DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX ix_analysis_stats_date ON analysis_stats (date);

CREATE TABLE data_governance_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    scope TEXT,
    affected_count INTEGER,
    reason TEXT NOT NULL,
    operator VARCHAR(100) NOT NULL DEFAULT 'system',
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL DEFAULT '',
    google_sub VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_users_email ON users (email);
CREATE INDEX ix_users_google_sub ON users (google_sub);

CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE INDEX ix_sessions_expires_at ON sessions (expires_at);

-- Intelligence Confidence Audit Engine (ICAE) tables

CREATE TABLE ice_protocols (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL UNIQUE,
    display_name VARCHAR(50) NOT NULL,
    rfc_refs TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE ice_test_runs (
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

CREATE INDEX ix_ice_test_runs_created ON ice_test_runs (created_at);
CREATE INDEX ix_ice_test_runs_version ON ice_test_runs (app_version);

CREATE TABLE ice_results (
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_ice_results_run ON ice_results (run_id);
CREATE INDEX ix_ice_results_protocol ON ice_results (protocol, layer);
CREATE INDEX ix_ice_results_case ON ice_results (case_id);

CREATE TABLE ice_maturity (
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
    CONSTRAINT ice_maturity_unique UNIQUE (protocol, layer)
);

CREATE TABLE ice_regressions (
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

CREATE INDEX ix_ice_regressions_protocol ON ice_regressions (protocol, layer, created_at);

-- Privacy-Respecting Site Analytics
-- No cookies, no PII, no IP addresses stored.
-- Unique visitors counted via daily-rotating salted hash (ephemeral, never persisted).

CREATE TABLE site_analytics (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    pageviews INTEGER NOT NULL DEFAULT 0,
    unique_visitors INTEGER NOT NULL DEFAULT 0,
    analyses_run INTEGER NOT NULL DEFAULT 0,
    unique_domains_analyzed INTEGER NOT NULL DEFAULT 0,
    referrer_sources JSONB NOT NULL DEFAULT '{}',
    top_pages JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_site_analytics_date ON site_analytics (date);

CREATE TABLE user_analyses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    analysis_id INTEGER NOT NULL REFERENCES domain_analyses(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT user_analyses_unique UNIQUE (user_id, analysis_id)
);

CREATE INDEX ix_user_analyses_user_id ON user_analyses (user_id, created_at DESC);
CREATE INDEX ix_user_analyses_analysis_id ON user_analyses (analysis_id);
