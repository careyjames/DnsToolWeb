import os
import re
import logging
import time
import secrets
import uuid
import requests as http_requests
from collections import defaultdict
from threading import Lock
from datetime import datetime, date
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, send_from_directory, g, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_compress import Compress
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import JSON, event
from dns_analyzer import DNSAnalyzer

# App version - format: YY.M.patch (bump last number for small changes)
APP_VERSION = "26.10.73"


class TraceIDFilter(logging.Filter):
    """Logging filter that adds trace_id to log records."""
    
    def filter(self, record):
        # Get trace_id from Flask's g object if available
        try:
            from flask import g, has_request_context
            if has_request_context() and hasattr(g, 'trace_id'):
                record.trace_id = g.trace_id
            else:
                record.trace_id = 'no-trace'
        except Exception:
            record.trace_id = 'no-trace'
        return True


def setup_structured_logging():
    """Configure structured logging with trace ID support."""
    # Create custom formatter with trace ID
    log_format = '%(asctime)s [%(levelname)s] [trace:%(trace_id)s] %(name)s: %(message)s'
    formatter = logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')
    
    # Get the root logger
    root_logger = logging.getLogger()
    # Use LOG_LEVEL env var, default to INFO in production (DEBUG is too verbose)
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))
    
    # Add trace ID filter to all handlers
    trace_filter = TraceIDFilter()
    
    # Configure handlers
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)
        handler.addFilter(trace_filter)
    
    # If no handlers exist, add a stream handler
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        handler.addFilter(trace_filter)
        root_logger.addHandler(handler)
    
    return trace_filter


# Initialize structured logging
_trace_filter = setup_structured_logging()

# Rate limiting configuration
RATE_LIMIT_WINDOW = 60  # 1 minute window
RATE_LIMIT_MAX_REQUESTS = 8  # 8 analyses per minute per IP
ANTI_REPEAT_WINDOW = 15  # 15 seconds anti-repeat (double-click protection only)


class InMemoryRateLimiter:
    """In-memory rate limiter with per-IP tracking.
    
    Uses atomic check-and-record to prevent race conditions with concurrent requests.
    """
    
    def __init__(self):
        self._requests = defaultdict(list)  # IP -> list of timestamps
        self._recent_analyses = {}  # (IP, domain) -> timestamp
        self._lock = Lock()
        self.backend = 'memory'
    
    def _cleanup_old_requests(self, ip: str, current_time: float):
        """Remove requests older than the rate limit window."""
        cutoff = current_time - RATE_LIMIT_WINDOW
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
    
    def _cleanup_old_analyses(self, current_time: float):
        """Remove anti-repeat entries older than the window."""
        cutoff = current_time - ANTI_REPEAT_WINDOW
        expired = [k for k, v in self._recent_analyses.items() if v < cutoff]
        for k in expired:
            del self._recent_analyses[k]
    
    def check_and_record(self, ip: str, domain: str) -> tuple[bool, str, int]:
        """Atomically check rate limit + anti-repeat and record if allowed.
        
        This prevents race conditions by checking and recording in one lock.
        
        Returns: (allowed, reason, wait_seconds)
            - allowed: True if request should proceed
            - reason: 'ok', 'rate_limit', or 'anti_repeat'
            - wait_seconds: Seconds to wait if blocked (0 if allowed)
        """
        current_time = time.time()
        key = (ip, domain.lower())
        
        with self._lock:
            # Cleanup old entries
            self._cleanup_old_requests(ip, current_time)
            self._cleanup_old_analyses(current_time)
            
            # Check rate limit first
            request_count = len(self._requests[ip])
            if request_count >= RATE_LIMIT_MAX_REQUESTS:
                oldest = min(self._requests[ip]) if self._requests[ip] else current_time
                seconds_until_reset = int(oldest + RATE_LIMIT_WINDOW - current_time) + 1
                return False, 'rate_limit', seconds_until_reset
            
            # Check anti-repeat
            if key in self._recent_analyses:
                last_time = self._recent_analyses[key]
                elapsed = current_time - last_time
                if elapsed < ANTI_REPEAT_WINDOW:
                    seconds_remaining = int(ANTI_REPEAT_WINDOW - elapsed) + 1
                    return False, 'anti_repeat', seconds_remaining
            
            # All checks passed - record immediately to prevent race conditions
            self._requests[ip].append(current_time)
            self._recent_analyses[key] = current_time
            
            return True, 'ok', 0
    
    def check_rate_limit(self, ip: str) -> tuple[bool, int]:
        """Check if IP is within rate limit (for testing only).
        
        Returns: (allowed, seconds_until_reset)
        """
        current_time = time.time()
        with self._lock:
            self._cleanup_old_requests(ip, current_time)
            request_count = len(self._requests[ip])
            
            if request_count >= RATE_LIMIT_MAX_REQUESTS:
                oldest = min(self._requests[ip]) if self._requests[ip] else current_time
                seconds_until_reset = int(oldest + RATE_LIMIT_WINDOW - current_time) + 1
                return False, seconds_until_reset
            
            return True, 0
    
    def check_anti_repeat(self, ip: str, domain: str) -> tuple[bool, int]:
        """Check if this is a repeat request (for testing only).
        
        Returns: (allowed, seconds_until_allowed)
        """
        current_time = time.time()
        key = (ip, domain.lower())
        
        with self._lock:
            self._cleanup_old_analyses(current_time)
            
            if key in self._recent_analyses:
                last_time = self._recent_analyses[key]
                elapsed = current_time - last_time
                if elapsed < ANTI_REPEAT_WINDOW:
                    seconds_remaining = int(ANTI_REPEAT_WINDOW - elapsed) + 1
                    return False, seconds_remaining
            
            return True, 0
    
    def record_request(self, ip: str, domain: str):
        """Record a request (for testing only - use check_and_record in production)."""
        current_time = time.time()
        with self._lock:
            self._requests[ip].append(current_time)
            self._recent_analyses[(ip, domain.lower())] = current_time


class RedisRateLimiter:
    """Redis-backed rate limiter for multi-worker scaling.
    
    Uses Redis sorted sets for atomic, distributed rate limiting.
    Falls back to in-memory if Redis connection fails.
    """
    
    def __init__(self, redis_url: str):
        import redis as redis_lib
        self._redis = redis_lib.from_url(redis_url, decode_responses=True)
        self._fallback = InMemoryRateLimiter()
        self.backend = 'redis'
        # Test connection
        try:
            self._redis.ping()
        except Exception as e:
            logging.warning(f"Redis connection failed, falling back to memory: {e}")
            self.backend = 'memory'
    
    def _get_rate_key(self, ip: str) -> str:
        return f"ratelimit:ip:{ip}"
    
    def _get_anti_repeat_key(self, ip: str, domain: str) -> str:
        return f"ratelimit:repeat:{ip}:{domain.lower()}"
    
    def check_and_record(self, ip: str, domain: str) -> tuple[bool, str, int]:
        """Atomically check and record using Redis pipeline."""
        if self.backend == 'memory':
            return self._fallback.check_and_record(ip, domain)
        
        try:
            current_time = time.time()
            rate_key = self._get_rate_key(ip)
            repeat_key = self._get_anti_repeat_key(ip, domain)
            
            # Use pipeline for atomicity
            pipe = self._redis.pipeline(True)
            
            # Remove old entries from rate limit set
            cutoff = current_time - RATE_LIMIT_WINDOW
            pipe.zremrangebyscore(rate_key, '-inf', cutoff)
            pipe.zcard(rate_key)
            pipe.zrange(rate_key, 0, 0, withscores=True)  # Get oldest
            
            # Check anti-repeat
            pipe.get(repeat_key)
            
            results = pipe.execute()
            request_count = results[1]
            oldest_entries = results[2]
            last_analysis = results[3]
            
            # Check rate limit
            if request_count >= RATE_LIMIT_MAX_REQUESTS:
                if oldest_entries:
                    oldest_time = float(oldest_entries[0][1])
                    seconds_until_reset = int(oldest_time + RATE_LIMIT_WINDOW - current_time) + 1
                else:
                    seconds_until_reset = RATE_LIMIT_WINDOW
                return False, 'rate_limit', max(1, seconds_until_reset)
            
            # Check anti-repeat
            if last_analysis:
                last_time = float(last_analysis)
                elapsed = current_time - last_time
                if elapsed < ANTI_REPEAT_WINDOW:
                    seconds_remaining = int(ANTI_REPEAT_WINDOW - elapsed) + 1
                    return False, 'anti_repeat', max(1, seconds_remaining)
            
            # All checks passed - record
            pipe2 = self._redis.pipeline(True)
            pipe2.zadd(rate_key, {str(current_time): current_time})
            pipe2.expire(rate_key, RATE_LIMIT_WINDOW + 10)
            pipe2.set(repeat_key, str(current_time), ex=ANTI_REPEAT_WINDOW + 5)
            pipe2.execute()
            
            return True, 'ok', 0
            
        except Exception as e:
            logging.warning(f"Redis error, using fallback: {e}")
            return self._fallback.check_and_record(ip, domain)
    
    def check_rate_limit(self, ip: str) -> tuple[bool, int]:
        """Check if IP is within rate limit."""
        if self.backend == 'memory':
            return self._fallback.check_rate_limit(ip)
        
        try:
            current_time = time.time()
            rate_key = self._get_rate_key(ip)
            
            # Remove old and count
            cutoff = current_time - RATE_LIMIT_WINDOW
            pipe = self._redis.pipeline(True)
            pipe.zremrangebyscore(rate_key, '-inf', cutoff)
            pipe.zcard(rate_key)
            pipe.zrange(rate_key, 0, 0, withscores=True)
            results = pipe.execute()
            
            request_count = results[1]
            oldest_entries = results[2]
            
            if request_count >= RATE_LIMIT_MAX_REQUESTS:
                if oldest_entries:
                    oldest_time = float(oldest_entries[0][1])
                    seconds_until_reset = int(oldest_time + RATE_LIMIT_WINDOW - current_time) + 1
                else:
                    seconds_until_reset = RATE_LIMIT_WINDOW
                return False, max(1, seconds_until_reset)
            
            return True, 0
            
        except Exception:
            return self._fallback.check_rate_limit(ip)
    
    def check_anti_repeat(self, ip: str, domain: str) -> tuple[bool, int]:
        """Check if this is a repeat request."""
        if self.backend == 'memory':
            return self._fallback.check_anti_repeat(ip, domain)
        
        try:
            current_time = time.time()
            repeat_key = self._get_anti_repeat_key(ip, domain)
            
            last_analysis = self._redis.get(repeat_key)
            if last_analysis:
                last_time = float(str(last_analysis))
                elapsed = current_time - last_time
                if elapsed < ANTI_REPEAT_WINDOW:
                    seconds_remaining = int(ANTI_REPEAT_WINDOW - elapsed) + 1
                    return False, max(1, seconds_remaining)
            
            return True, 0
            
        except Exception:
            return self._fallback.check_anti_repeat(ip, domain)
    
    def record_request(self, ip: str, domain: str):
        """Record a request (for testing)."""
        if self.backend == 'memory':
            return self._fallback.record_request(ip, domain)
        
        try:
            current_time = time.time()
            rate_key = self._get_rate_key(ip)
            repeat_key = self._get_anti_repeat_key(ip, domain)
            
            pipe = self._redis.pipeline(True)
            pipe.zadd(rate_key, {str(current_time): current_time})
            pipe.expire(rate_key, RATE_LIMIT_WINDOW + 10)
            pipe.set(repeat_key, str(current_time), ex=ANTI_REPEAT_WINDOW + 5)
            pipe.execute()
            
        except Exception:
            self._fallback.record_request(ip, domain)


# Backwards compatibility alias
RateLimiter = InMemoryRateLimiter


def create_rate_limiter():
    """Create the appropriate rate limiter based on environment.
    
    Uses Redis if REDIS_URL is set, otherwise in-memory.
    """
    redis_url = os.environ.get('REDIS_URL')
    if redis_url:
        try:
            limiter = RedisRateLimiter(redis_url)
            logging.info(f"Rate limiter using backend: {limiter.backend}")
            return limiter
        except Exception as e:
            logging.warning(f"Failed to create Redis rate limiter: {e}")
    
    limiter = InMemoryRateLimiter()
    logging.info("Rate limiter using backend: memory")
    logging.warning("Rate limiter: in-memory backend is per-process only. "
                    "Set REDIS_URL for shared rate limiting across workers.")
    return limiter


# Global rate limiter instance
rate_limiter = create_rate_limiter()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable gzip/brotli compression
Compress(app)

# Static files cache: 1 year (files are versioned via APP_VERSION)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 31536000

# Configure the database - use PostgreSQL from environment
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Initialize DNS analyzer
dns_analyzer = DNSAnalyzer()

@app.before_request
def setup_request_context():
    """Set up request context including CSP nonce, trace ID, and CSRF validation."""
    g.csp_nonce = secrets.token_urlsafe(16)
    g.trace_id = str(uuid.uuid4())[:8]
    g.request_start_time = time.time()

    if request.method == 'POST':
        from flask import session, abort
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or token != session.get('csrf_token'):
            abort(403)

def generate_csrf_token():
    """Generate or return existing CSRF token for the session."""
    from flask import session
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

@app.context_processor
def inject_globals():
    """Inject app version, CSP nonce, and CSRF token into all templates."""
    return {
        'app_version': APP_VERSION,
        'csp_nonce': getattr(g, 'csp_nonce', ''),
        'csrf_token': generate_csrf_token()
    }

@app.template_filter('country_flag')
def country_flag_filter(code):
    """Convert a 2-letter country code to a flag emoji."""
    if not code or len(code) != 2:
        return ''
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())

@app.after_request
def add_security_headers(response):
    """Add security headers and log request completion with trace ID."""
    # Log request completion with timing
    if hasattr(g, 'request_start_time'):
        duration_ms = (time.time() - g.request_start_time) * 1000
        logging.info(f"Request completed: {request.method} {request.path} -> {response.status_code} ({duration_ms:.1f}ms)")
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Enable HSTS (Strict Transport Security) - preload ready
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    # Control referrer information
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Cross-Origin headers for additional security
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    if request.path.startswith('/static/images/'):
        response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
    else:
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    # Content Security Policy - balanced for security AND real-world compatibility
    # - script-src uses nonces (critical for XSS prevention)
    # - style-src uses 'unsafe-inline' (acceptable - inline style attrs can't use nonces)
    # - Bootstrap CSS self-hosted (no external font/style CDN needed)
    nonce = getattr(g, 'csp_nonce', '')
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data: https:; "
        "object-src 'none'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "upgrade-insecure-requests;"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

class DomainAnalysis(db.Model):
    """Store DNS analysis results for domains."""
    __tablename__ = 'domain_analyses'
    __table_args__ = (
        db.Index('ix_domain_analyses_created_at', 'created_at'),
        db.Index('ix_domain_analyses_success_results', 'analysis_success', 'created_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    ascii_domain = db.Column(db.String(255), nullable=False, index=True)
    
    # DNS Records (JSON fields)
    basic_records = db.Column(JSON)
    authoritative_records = db.Column(JSON)
    
    # Email Security Analysis
    spf_status = db.Column(db.String(20))
    spf_records = db.Column(JSON)
    dmarc_status = db.Column(db.String(20))
    dmarc_policy = db.Column(db.String(20))
    dmarc_records = db.Column(JSON)
    dkim_status = db.Column(db.String(20))
    dkim_selectors = db.Column(JSON)
    
    # Registrar Information
    registrar_name = db.Column(db.String(255))
    registrar_source = db.Column(db.String(20))
    
    # Visitor geolocation
    country_code = db.Column(db.String(10))
    country_name = db.Column(db.String(100))
    
    # Subdomain Discovery (Certificate Transparency)
    ct_subdomains = db.Column(JSON)
    
    # Complete analysis results (stores everything for full history playback)
    # NOT NULL enforced at database level — no record may exist without complete data
    full_results = db.Column(JSON, nullable=False)
    
    # Analysis metadata
    analysis_success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    analysis_duration = db.Column(db.Float)  # seconds
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    SCHEMA_VERSION = 2

    REQUIRED_SECTIONS = [
        'basic_records', 'spf_analysis', 'dmarc_analysis',
        'dkim_analysis', 'registrar_info', 'posture',
        'dane_analysis', 'mta_sts_analysis', 'tlsrpt_analysis',
        'bimi_analysis', 'caa_analysis', 'dnssec_analysis',
    ]

    def __init__(self, **kwargs):
        if 'full_results' in kwargs and kwargs['full_results'] is not None:
            kwargs['full_results']['_schema_version'] = self.SCHEMA_VERSION
        super().__init__(**kwargs)

    def validate_integrity(self):
        if not self.full_results:
            raise ValueError(f"DomainAnalysis {self.domain}: full_results is empty")
        missing = [s for s in self.REQUIRED_SECTIONS if s not in self.full_results]
        if missing:
            raise ValueError(f"DomainAnalysis {self.domain}: missing sections: {missing}")
        empty = [s for s in self.REQUIRED_SECTIONS if not self.full_results.get(s)]
        if empty:
            raise ValueError(f"DomainAnalysis {self.domain}: empty sections: {empty}")
        if '_schema_version' not in self.full_results:
            self.full_results['_schema_version'] = self.SCHEMA_VERSION
        return True

    def __repr__(self):
        return f'<DomainAnalysis {self.domain}>'
    
    def to_dict(self):
        """Convert analysis to dictionary format."""
        return {
            'id': self.id,
            'domain': self.domain,
            'ascii_domain': self.ascii_domain,
            'basic_records': self.basic_records,
            'authoritative_records': self.authoritative_records,
            'spf_analysis': {
                'status': self.spf_status,
                'records': self.spf_records
            },
            'dmarc_analysis': {
                'status': self.dmarc_status,
                'policy': self.dmarc_policy,
                'records': self.dmarc_records
            },
            'dkim_analysis': {
                'status': self.dkim_status,
                'selectors': self.dkim_selectors
            },
            'registrar_info': {
                'registrar': self.registrar_name,
                'source': self.registrar_source
            },
            'analysis_success': self.analysis_success,
            'error_message': self.error_message,
            'analysis_duration': self.analysis_duration,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class AnalysisStats(db.Model):
    """Store daily statistics for DNS analyses."""
    __tablename__ = 'analysis_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, unique=True, index=True)
    total_analyses = db.Column(db.Integer, default=0)
    successful_analyses = db.Column(db.Integer, default=0)
    failed_analyses = db.Column(db.Integer, default=0)
    unique_domains = db.Column(db.Integer, default=0)
    avg_analysis_time = db.Column(db.Float, default=0.0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def __repr__(self):
        return f'<AnalysisStats {self.date}>'

@event.listens_for(DomainAnalysis, 'before_insert')
def validate_before_insert(mapper, connection, target):
    target.validate_integrity()

@event.listens_for(DomainAnalysis, 'before_update')
def validate_before_update(mapper, connection, target):
    if target.full_results is not None:
        target.validate_integrity()

# Create tables - wrapped in try-except to prevent startup failures
try:
    with app.app_context():
        db.create_all()
        logging.info("Database tables created successfully")
except Exception as e:
    logging.warning(f"Could not create database tables on startup: {e}")
    logging.warning("Application will start without database. Database features may not work.")

@app.route('/')
def index():
    """Main page with domain input form."""
    return render_template('index.html')

@app.route('/robots.txt')
def robots():
    """Serve robots.txt for search engines."""
    return send_from_directory('static', 'robots.txt', mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap():
    """Generate dynamic sitemap.xml with automatic lastmod dates."""
    today = date.today().isoformat()
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    pages = [
        {'loc': 'https://dnstool.it-help.tech/', 'changefreq': 'weekly', 'priority': '1.0'},
        {'loc': 'https://dnstool.it-help.tech/history', 'changefreq': 'daily', 'priority': '0.6'},
        {'loc': 'https://dnstool.it-help.tech/stats', 'changefreq': 'daily', 'priority': '0.5'},
        {'loc': 'https://dnstool.it-help.tech/statistics', 'changefreq': 'daily', 'priority': '0.5'},
    ]
    for page in pages:
        xml += '  <url>\n'
        xml += f'    <loc>{page["loc"]}</loc>\n'
        xml += f'    <lastmod>{today}</lastmod>\n'
        xml += f'    <changefreq>{page["changefreq"]}</changefreq>\n'
        xml += f'    <priority>{page["priority"]}</priority>\n'
        xml += '  </url>\n'
    xml += '</urlset>\n'
    from flask import Response
    return Response(xml, mimetype='application/xml')

@app.route('/llms.txt')
def llms():
    """Serve llms.txt for AI crawlers."""
    return send_from_directory('static', 'llms.txt', mimetype='text/plain')

@app.route('/llms-full.txt')
def llms_full():
    """Serve llms-full.txt for AI crawlers."""
    return send_from_directory('static', 'llms-full.txt', mimetype='text/plain')

@app.route('/manifest.json')
def manifest():
    """Serve PWA manifest from root URL."""
    return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route('/sw.js')
def service_worker():
    """Serve service worker from root scope for PWA installability."""
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

@app.route('/proxy/bimi-logo')
def proxy_bimi_logo():
    """Proxy BIMI logos to avoid CORS issues with external SVGs."""
    import ipaddress
    import socket
    from urllib.parse import urlparse

    import requests
    from flask import Response

    MAX_RESPONSE_BYTES = 512 * 1024

    logo_url = request.args.get('url')
    if not logo_url:
        return 'Missing URL parameter', 400

    parsed = urlparse(logo_url)

    if parsed.scheme != 'https':
        return 'Only HTTPS URLs allowed', 400

    if not parsed.hostname:
        return 'Invalid URL', 400

    try:
        resolved_ips = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return 'Could not resolve hostname', 400

    for _family, _type, _proto, _canonname, sockaddr in resolved_ips:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return 'URL points to a disallowed address', 400

    try:
        resp = requests.get(logo_url, timeout=5, allow_redirects=False, headers={
            'User-Agent': 'DNS-Analyzer/1.0 BIMI-Logo-Fetcher'
        }, stream=True)

        redirect_count = 0
        max_redirects = 5
        while resp.status_code in (301, 302, 303, 307, 308) and redirect_count < max_redirects:
            redirect_count += 1
            redirect_url = resp.headers.get('Location')
            if not redirect_url:
                return 'Redirect without Location header', 502

            r_parsed = urlparse(redirect_url)
            if r_parsed.scheme != 'https':
                return 'Redirect to non-HTTPS URL blocked', 400
            if not r_parsed.hostname:
                return 'Invalid redirect URL', 400

            try:
                r_ips = socket.getaddrinfo(r_parsed.hostname, None)
            except socket.gaierror:
                return 'Could not resolve redirect hostname', 400
            for _f, _t, _p, _c, sa in r_ips:
                r_ip = ipaddress.ip_address(sa[0])
                if r_ip.is_private or r_ip.is_loopback or r_ip.is_link_local or r_ip.is_reserved:
                    return 'Redirect points to a disallowed address', 400

            resp.close()
            resp = requests.get(redirect_url, timeout=5, allow_redirects=False, headers={
                'User-Agent': 'DNS-Analyzer/1.0 BIMI-Logo-Fetcher'
            }, stream=True)

        if resp.status_code != 200:
            return f'Failed to fetch logo: {resp.status_code}', 502

        content_type = resp.headers.get('Content-Type', '')
        if 'svg' not in content_type.lower() and 'image' not in content_type.lower():
            return 'Response is not an image', 400

        body = resp.content
        if len(body) > MAX_RESPONSE_BYTES:
            return 'Response too large', 400

        upstream_ct = resp.headers.get('Content-Type', 'image/svg+xml')

        return Response(
            body,
            content_type=upstream_ct,
            headers={
                'Cache-Control': 'public, max-age=3600',
                'X-Content-Type-Options': 'nosniff'
            }
        )
    except requests.Timeout:
        return 'Timeout fetching logo', 504
    except Exception as e:
        logging.error(f"Error proxying BIMI logo: {e}")
        return 'Error fetching logo', 500

@app.route('/debug-rdap/<domain>')
def debug_rdap(domain):
    """Debug endpoint to test RDAP directly."""
    import requests
    results = []
    
    # Test endpoints
    endpoints = [
        ('CentralNic .tech', f'https://rdap.centralnic.com/tech/domain/{domain}'),
        ('rdap.org', f'https://rdap.org/domain/{domain}'),
        ('Verisign .com', f'https://rdap.verisign.com/com/v1/domain/{domain}'),
    ]
    
    headers = {'Accept': 'application/rdap+json', 'User-Agent': 'DNS-Analyzer/1.0'}
    
    for name, url in endpoints:
        start = time.time()
        try:
            resp = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
            elapsed = time.time() - start
            if resp.status_code < 400:
                data = resp.json()
                registrar = None
                for ent in data.get('entities', []):
                    if 'registrar' in [r.lower() for r in ent.get('roles', [])]:
                        registrar = ent.get('handle') or ent.get('name')
                        break
                results.append({
                    'name': name,
                    'url': url,
                    'status': resp.status_code,
                    'time': f'{elapsed:.2f}s',
                    'registrar': registrar,
                    'success': True
                })
            else:
                results.append({
                    'name': name,
                    'url': url,
                    'status': resp.status_code,
                    'time': f'{elapsed:.2f}s',
                    'success': False,
                    'error': f'HTTP {resp.status_code}'
                })
        except Exception as e:
            elapsed = time.time() - start
            results.append({
                'name': name,
                'url': url,
                'time': f'{elapsed:.2f}s',
                'success': False,
                'error': f'{type(e).__name__}: {str(e)[:100]}'
            })
    
    return jsonify({'domain': domain, 'results': results})

@app.route('/debug-whodap/<domain>')
def debug_whodap(domain):
    """Debug endpoint to test whodap library directly."""
    import whodap
    
    # Parse domain
    parts = domain.rsplit('.', 1)
    if len(parts) != 2:
        return jsonify({'error': 'Invalid domain format'})
    
    domain_name, tld = parts[0], parts[1]
    
    try:
        start = time.time()
        response = whodap.lookup_domain(domain=domain_name, tld=tld)
        elapsed = time.time() - start
        
        # Get the raw dict
        data = response.to_dict()
        
        # Extract registrar
        registrar = None
        entities = data.get('entities', [])
        for ent in entities:
            roles = [r.lower() for r in ent.get('roles', [])]
            if 'registrar' in roles:
                vcard = ent.get('vcardArray', [])
                if len(vcard) == 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if len(item) >= 4 and item[0] == 'fn':
                            registrar = item[3]
                            break
                if not registrar:
                    registrar = ent.get('handle')
                break
        
        return jsonify({
            'success': True,
            'domain': domain,
            'time': f'{elapsed:.2f}s',
            'registrar': registrar,
            'entity_count': len(entities),
            'keys': list(data.keys())
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'domain': domain,
            'error': f'{type(e).__name__}: {str(e)}'
        })

def get_client_ip() -> str:
    """Get the client's real IP address, accounting for proxies."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def lookup_country(ip: str) -> dict:
    """Look up country from IP address using free ip-api.com service.
    Returns {'code': 'US', 'name': 'United States'} or empty dict on failure.
    Non-blocking: fails silently so it never delays analysis."""
    if not ip or ip in ('127.0.0.1', '::1', 'localhost'):
        logging.debug(f"[GEO] Skipping local IP: {ip}")
        return {}
    try:
        resp = http_requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,countryCode,country',
            timeout=2
        )
        if resp.status_code == 200:
            data = resp.json()
            logging.info(f"[GEO] IP={ip} -> {data}")
            if data.get('status') == 'success':
                return {
                    'code': data.get('countryCode', ''),
                    'name': data.get('country', '')
                }
        else:
            logging.warning(f"[GEO] IP={ip} -> HTTP {resp.status_code}")
    except Exception as e:
        logging.warning(f"[GEO] IP={ip} -> error: {e}")
    return {}


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Analyze DNS records for the submitted domain."""
    # Get domain from form (POST) or query string (GET)
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        dkim_selector1 = request.form.get('dkim_selector1', '').strip()
        dkim_selector2 = request.form.get('dkim_selector2', '').strip()
    else:
        domain = request.args.get('domain', '').strip()
        dkim_selector1 = request.args.get('dkim_selector1', '').strip()
        dkim_selector2 = request.args.get('dkim_selector2', '').strip()
    
    custom_selectors = []
    for sel in [dkim_selector1, dkim_selector2]:
        if sel:
            sel = re.sub(r'[^a-zA-Z0-9._-]', '', sel)[:63]
            sel = sel.rstrip('.').removesuffix('._domainkey').removesuffix('._domainkey.')
            if sel:
                custom_selectors.append(f"{sel}._domainkey")
    
    if not domain:
        flash('Please enter a domain name.', 'danger')
        return redirect(url_for('index'))
    
    # Validate domain
    if not dns_analyzer.validate_domain(domain):
        flash(f'Invalid domain name: {domain}', 'danger')
        return redirect(url_for('index'))
    
    # Get client IP for rate limiting and geo lookup
    client_ip = get_client_ip()
    geo = lookup_country(client_ip)
    
    # Atomic check and record (prevents race conditions with concurrent requests)
    allowed, reason, wait_seconds = rate_limiter.check_and_record(client_ip, domain)
    if not allowed:
        # Check if this was a re-analyze (has refresh param) - redirect back to results page
        if request.args.get('refresh'):
            # Find the most recent analysis for this domain to redirect back to
            recent = DomainAnalysis.query.filter_by(domain=domain).order_by(
                DomainAnalysis.created_at.desc()
            ).first()
            if recent:
                return redirect(url_for('view_analysis_static', analysis_id=recent.id, 
                                       wait_seconds=wait_seconds, wait_reason=reason))
        # Otherwise return to index with countdown
        return redirect(url_for('index', wait_seconds=wait_seconds, wait_domain=domain, wait_reason=reason))
    
    start_time = time.time()
    analysis_success = True
    error_message = None
    
    try:
        # Convert to ASCII for IDNA domains
        ascii_domain = dns_analyzer.domain_to_ascii(domain)
        
        # Perform DNS analysis
        results = dns_analyzer.analyze_domain(ascii_domain, custom_dkim_selectors=custom_selectors)
        
        # Calculate analysis duration
        analysis_duration = time.time() - start_time
        
        # Save analysis to database (integrity validated by before_insert listener)
        try:
            analysis = DomainAnalysis(
                domain=domain,
                ascii_domain=ascii_domain,
                basic_records=results.get('basic_records', {}),
                authoritative_records=results.get('authoritative_records', {}),
                spf_status=results.get('spf_analysis', {}).get('status'),
                spf_records=results.get('spf_analysis', {}).get('records', []),
                dmarc_status=results.get('dmarc_analysis', {}).get('status'),
                dmarc_policy=results.get('dmarc_analysis', {}).get('policy'),
                dmarc_records=results.get('dmarc_analysis', {}).get('records', []),
                dkim_status=results.get('dkim_analysis', {}).get('status'),
                dkim_selectors=results.get('dkim_analysis', {}).get('selectors', {}),
                registrar_name=results.get('registrar_info', {}).get('registrar'),
                registrar_source=results.get('registrar_info', {}).get('source'),
                ct_subdomains=results.get('ct_subdomains'),
                full_results=results,
                country_code=geo.get('code'),
                country_name=geo.get('name'),
                analysis_success=True,
                analysis_duration=analysis_duration
            )
            db.session.add(analysis)
            db.session.commit()
        except (ValueError, Exception) as save_err:
            db.session.rollback()
            logging.warning(f"Could not save analysis for {domain}: {save_err}")
            analysis = None
        
        update_daily_stats(analysis_success=True, duration=analysis_duration, domain=domain)
        
        return render_template('results.html', 
                             domain=domain, 
                             ascii_domain=ascii_domain,
                             results=results,
                             analysis_id=analysis.id if analysis else None,
                             analysis_duration=analysis_duration,
                             analysis_timestamp=analysis.created_at if analysis else datetime.utcnow())
        
    except Exception as e:
        analysis_duration = time.time() - start_time
        error_message = str(e)
        logging.error(f"Error analyzing domain {domain}: {e}")
        
        try:
            update_daily_stats(analysis_success=False, duration=analysis_duration, domain=domain)
        except Exception:
            pass
        
        flash('An internal error occurred. Please try again.', 'danger')
        return redirect(url_for('index'))

def update_daily_stats(analysis_success: bool, duration: float, domain: str):
    """Update daily statistics for analyses."""
    today = date.today()
    
    try:
        stats = AnalysisStats.query.filter_by(date=today).first()
        if not stats:
            stats = AnalysisStats(
                date=today,
                total_analyses=0,
                successful_analyses=0,
                failed_analyses=0,
                unique_domains=0,
                avg_analysis_time=0.0
            )
            db.session.add(stats)
        
        # Ensure fields are not None
        stats.total_analyses = (stats.total_analyses or 0) + 1
        if analysis_success:
            stats.successful_analyses = (stats.successful_analyses or 0) + 1
        else:
            stats.failed_analyses = (stats.failed_analyses or 0) + 1
        
        # Update average analysis time
        current_avg = stats.avg_analysis_time or 0.0
        if stats.total_analyses > 1:
            stats.avg_analysis_time = ((current_avg * (stats.total_analyses - 1)) + duration) / stats.total_analyses
        else:
            stats.avg_analysis_time = duration
        
        # Count unique domains today
        unique_count = db.session.query(DomainAnalysis.domain).filter(
            db.func.date(DomainAnalysis.created_at) == today
        ).distinct().count()
        stats.unique_domains = unique_count
        
        db.session.commit()
    except Exception as e:
        logging.error(f"Error updating daily stats: {e}")
        db.session.rollback()

@app.route('/history')
def history():
    """View analysis history with optional domain search."""
    page = request.args.get('page', 1, type=int)
    search_domain = request.args.get('domain', '', type=str).strip().lower()
    per_page = 20
    
    query = DomainAnalysis.query.filter(
        DomainAnalysis.full_results.isnot(None),
        DomainAnalysis.analysis_success == True
    )
    
    if search_domain:
        search_pattern = f"%{search_domain}%"
        query = query.filter(
            db.or_(
                DomainAnalysis.domain.ilike(search_pattern),
                DomainAnalysis.ascii_domain.ilike(search_pattern)
            )
        )
    
    analyses = query.order_by(
        DomainAnalysis.created_at.desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('history.html', analyses=analyses, search_domain=search_domain)

@app.route('/analysis/<int:analysis_id>')
def view_analysis(analysis_id):
    """View a specific analysis - ALWAYS performs fresh lookup."""
    analysis = DomainAnalysis.query.get_or_404(analysis_id)
    
    # ALWAYS do a fresh lookup - never show cached/stale data
    domain = analysis.domain
    ascii_domain = dns_analyzer.domain_to_ascii(domain)
    
    # Get client IP for rate limiting and geo lookup
    client_ip = get_client_ip()
    geo = lookup_country(client_ip)
    
    # Atomic check and record (prevents race conditions with concurrent requests)
    allowed, reason, wait_seconds = rate_limiter.check_and_record(client_ip, domain)
    if not allowed:
        # Return to index with wait_seconds for visual countdown (consistent UX)
        return redirect(url_for('index', wait_seconds=wait_seconds, wait_domain=domain, wait_reason=reason))
    
    start_time = time.time()
    results = dns_analyzer.analyze_domain(ascii_domain)
    analysis_duration = time.time() - start_time
    
    # Update the existing record with fresh data
    analysis.basic_records = results.get('basic_records', {})
    analysis.authoritative_records = results.get('authoritative_records', {})
    analysis.spf_status = results.get('spf_analysis', {}).get('status')
    analysis.spf_records = results.get('spf_analysis', {}).get('records', [])
    analysis.dmarc_status = results.get('dmarc_analysis', {}).get('status')
    analysis.dmarc_policy = results.get('dmarc_analysis', {}).get('policy')
    analysis.dmarc_records = results.get('dmarc_analysis', {}).get('records', [])
    analysis.dkim_status = results.get('dkim_analysis', {}).get('status')
    analysis.dkim_selectors = results.get('dkim_analysis', {}).get('selectors', {})
    analysis.registrar_name = results.get('registrar_info', {}).get('registrar')
    analysis.registrar_source = results.get('registrar_info', {}).get('source')
    analysis.ct_subdomains = results.get('ct_subdomains')
    results['_schema_version'] = DomainAnalysis.SCHEMA_VERSION
    analysis.full_results = results
    analysis.country_code = geo.get('code') or analysis.country_code
    analysis.country_name = geo.get('name') or analysis.country_name
    analysis.analysis_duration = analysis_duration
    
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    return render_template('results.html',
                         domain=domain,
                         ascii_domain=ascii_domain,
                         results=results,
                         analysis_id=analysis.id,
                         analysis_duration=analysis_duration,
                         analysis_timestamp=analysis.updated_at or analysis.created_at,
                         from_history=False)

def normalize_results(full_results):
    """Normalize stored full_results for rendering. Ensures forward/backward compatibility.
    
    When new sections are added to the analyzer, old records won't have them.
    This function fills in safe defaults so templates never crash on missing keys.
    Schema version is used to know what transformations are needed.
    """
    if not full_results:
        return None
    
    schema_v = full_results.get('_schema_version', 1)
    
    defaults = {
        'basic_records': {},
        'authoritative_records': {},
        'spf_analysis': {'status': 'unknown', 'records': []},
        'dmarc_analysis': {'status': 'unknown', 'policy': None, 'records': []},
        'dkim_analysis': {'status': 'unknown', 'selectors': {}},
        'registrar_info': {'registrar': None, 'source': None},
        'posture': {'state': 'unknown', 'label': 'Unknown'},
        'dane_analysis': {'status': 'info', 'has_dane': False, 'tlsa_records': [], 'issues': []},
        'mta_sts_analysis': {'status': 'warning'},
        'tlsrpt_analysis': {'status': 'warning'},
        'bimi_analysis': {'status': 'warning'},
        'caa_analysis': {'status': 'warning'},
        'dnssec_analysis': {'status': 'warning'},
        'ct_subdomains': {},
        'mail_posture': {'classification': 'unknown'},
    }
    
    for key, default_val in defaults.items():
        if key not in full_results:
            full_results[key] = default_val
    
    return full_results

@app.route('/analysis/<int:analysis_id>/view')
def view_analysis_static(analysis_id):
    """View a specific analysis WITHOUT re-analyzing (for rate limit redirects)."""
    analysis = DomainAnalysis.query.get_or_404(analysis_id)
    
    domain = analysis.domain
    ascii_domain = dns_analyzer.domain_to_ascii(domain)
    
    # Get wait_seconds from query params (for countdown display)
    wait_seconds = request.args.get('wait_seconds', type=int)
    wait_reason = request.args.get('wait_reason', '')
    
    if not analysis.full_results:
        flash('This report is no longer available. Please re-analyze the domain for a full report.', 'warning')
        return redirect(url_for('index'))
    
    results = normalize_results(analysis.full_results)
    
    return render_template('results.html',
                         domain=domain,
                         ascii_domain=ascii_domain,
                         results=results,
                         analysis_id=analysis.id,
                         analysis_duration=analysis.analysis_duration,
                         analysis_timestamp=analysis.updated_at or analysis.created_at,
                         from_history=True,
                         wait_seconds=wait_seconds,
                         wait_reason=wait_reason)

@app.route('/statistics')
def statistics_redirect():
    """Redirect /statistics to /stats for URL consistency."""
    return redirect(url_for('stats'))

@app.route('/stats')
def stats():
    """View analysis statistics."""
    # Get recent daily stats
    recent_stats = AnalysisStats.query.order_by(
        AnalysisStats.date.desc()
    ).limit(30).all()
    
    # Get overall statistics
    total_analyses = DomainAnalysis.query.count()
    successful_analyses = DomainAnalysis.query.filter_by(analysis_success=True).count()
    unique_domains = db.session.query(DomainAnalysis.domain).distinct().count()
    
    # Get most analyzed domains
    popular_domains = db.session.query(
        DomainAnalysis.domain,
        db.func.count(DomainAnalysis.id).label('count')
    ).group_by(DomainAnalysis.domain).order_by(
        db.func.count(DomainAnalysis.id).desc()
    ).limit(10).all()
    
    # Get country distribution
    country_stats = db.session.query(
        DomainAnalysis.country_code,
        DomainAnalysis.country_name,
        db.func.count(DomainAnalysis.id).label('count')
    ).filter(
        DomainAnalysis.country_code.isnot(None),
        DomainAnalysis.country_code != ''
    ).group_by(
        DomainAnalysis.country_code,
        DomainAnalysis.country_name
    ).order_by(
        db.func.count(DomainAnalysis.id).desc()
    ).limit(20).all()
    
    return render_template('stats.html',
                         recent_stats=recent_stats,
                         total_analyses=total_analyses,
                         successful_analyses=successful_analyses,
                         unique_domains=unique_domains,
                         popular_domains=popular_domains,
                         country_stats=country_stats)

@app.route('/export/json')
def export_json():
    """Export all successful analyses as streaming NDJSON (one JSON object per line)."""
    import json as json_mod

    def generate():
        page = 1
        per_page = 100
        while True:
            analyses = DomainAnalysis.query.filter(
                DomainAnalysis.full_results.isnot(None),
                DomainAnalysis.analysis_success == True
            ).order_by(
                DomainAnalysis.created_at.desc()
            ).paginate(page=page, per_page=per_page, error_out=False)

            if not analyses.items:
                break

            for a in analyses.items:
                record = {
                    'id': a.id,
                    'domain': a.domain,
                    'ascii_domain': a.ascii_domain,
                    'created_at': a.created_at.isoformat() if a.created_at else None,
                    'updated_at': a.updated_at.isoformat() if a.updated_at else None,
                    'analysis_duration': a.analysis_duration,
                    'country_code': a.country_code,
                    'country_name': a.country_name,
                    'full_results': a.full_results,
                }
                yield json_mod.dumps(record, default=str) + '\n'

            if not analyses.has_next:
                break
            page += 1

    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return Response(
        stream_with_context(generate()),
        mimetype='application/x-ndjson',
        headers={
            'Content-Disposition': f'attachment; filename=dns_tool_export_{timestamp}.ndjson'
        }
    )

@app.route('/api/analysis/<int:analysis_id>')
def api_analysis(analysis_id):
    """API endpoint to get analysis data as JSON."""
    analysis = DomainAnalysis.query.get_or_404(analysis_id)
    return jsonify(analysis.to_dict())

@app.route('/api/subdomains/<path:domain>')
def api_subdomains(domain):
    """Discover subdomains via Certificate Transparency logs."""
    from flask import jsonify
    
    domain = domain.strip().lower()
    if not dns_analyzer.validate_domain(domain):
        return jsonify({'status': 'error', 'message': 'Invalid domain'}), 400
    
    result = dns_analyzer.discover_subdomains(domain)
    return jsonify(result)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    flash('An internal error occurred. Please try again.', 'danger')
    return render_template('index.html'), 500

if __name__ == '__main__':
    # Debug mode controlled by environment - disabled in production via gunicorn
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)  # nosec B104 B201
