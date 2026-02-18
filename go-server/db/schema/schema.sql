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
    posture_hash VARCHAR(64)
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
