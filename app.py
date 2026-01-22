import os
import logging
import time
from datetime import datetime, date
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import JSON
from dns_analyzer import DNSAnalyzer

# App version - format: YY.M.patch (bump last number for small changes)
APP_VERSION = "26.1.7"

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dns-tool-secret-key")

# Configure the database - using SQLite for reliability
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dns_analysis.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Initialize DNS analyzer
dns_analyzer = DNSAnalyzer()

@app.context_processor
def inject_version():
    """Inject app version into all templates."""
    return {'app_version': APP_VERSION}

class DomainAnalysis(db.Model):
    """Store DNS analysis results for domains."""
    __tablename__ = 'domain_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    ascii_domain = db.Column(db.String(255), nullable=False)
    
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
    
    # Analysis metadata
    analysis_success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    analysis_duration = db.Column(db.Float)  # seconds
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
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
    
    def __repr__(self):
        return f'<AnalysisStats {self.date}>'

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

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Analyze DNS records for the submitted domain."""
    if request.method == 'GET':
        return redirect(url_for('index'))
        
    domain = request.form.get('domain', '').strip()
    
    if not domain:
        flash('Please enter a domain name.', 'danger')
        return redirect(url_for('index'))
    
    # Validate domain
    if not dns_analyzer.validate_domain(domain):
        flash(f'Invalid domain name: {domain}', 'danger')
        return redirect(url_for('index'))
    
    start_time = time.time()
    analysis_success = True
    error_message = None
    
    try:
        # Convert to ASCII for IDNA domains
        ascii_domain = dns_analyzer.domain_to_ascii(domain)
        
        # Perform DNS analysis
        results = dns_analyzer.analyze_domain(ascii_domain)
        
        # Calculate analysis duration
        analysis_duration = time.time() - start_time
        
        # Save analysis to database
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
            analysis_success=True,
            analysis_duration=analysis_duration
        )
        
        # Add propagation data to results for template if not stored in DB
        # We don't change the model schema in fast mode to avoid migration issues
        
        db.session.add(analysis)
        db.session.commit()
        
        # Update daily statistics
        update_daily_stats(analysis_success=True, duration=analysis_duration, domain=domain)
        
        return render_template('results.html', 
                             domain=domain, 
                             ascii_domain=ascii_domain,
                             results=results,
                             analysis_id=analysis.id)
        
    except Exception as e:
        analysis_duration = time.time() - start_time
        error_message = str(e)
        logging.error(f"Error analyzing domain {domain}: {e}")
        
        # Save failed analysis to database
        analysis = DomainAnalysis(
            domain=domain,
            ascii_domain=dns_analyzer.domain_to_ascii(domain),
            analysis_success=False,
            error_message=error_message,
            analysis_duration=analysis_duration
        )
        
        try:
            db.session.add(analysis)
            db.session.commit()
            update_daily_stats(analysis_success=False, duration=analysis_duration, domain=domain)
        except Exception:
            pass  # Don't fail if we can't save the error
        
        flash(f'Error analyzing domain: {error_message}', 'danger')
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
    """View analysis history."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    analyses = DomainAnalysis.query.order_by(
        DomainAnalysis.created_at.desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('history.html', analyses=analyses)

@app.route('/analysis/<int:analysis_id>')
def view_analysis(analysis_id):
    """View a specific analysis - ALWAYS performs fresh lookup."""
    analysis = DomainAnalysis.query.get_or_404(analysis_id)
    
    # ALWAYS do a fresh lookup - never show cached/stale data
    domain = analysis.domain
    ascii_domain = dns_analyzer.domain_to_ascii(domain)
    
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
    analysis.analysis_duration = analysis_duration
    analysis.analyzed_at = datetime.utcnow()
    
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    return render_template('results.html',
                         domain=domain,
                         ascii_domain=ascii_domain,
                         results=results,
                         analysis_id=analysis.id,
                         from_history=False)

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
    
    return render_template('stats.html',
                         recent_stats=recent_stats,
                         total_analyses=total_analyses,
                         successful_analyses=successful_analyses,
                         unique_domains=unique_domains,
                         popular_domains=popular_domains)

@app.route('/api/analysis/<int:analysis_id>')
def api_analysis(analysis_id):
    """API endpoint to get analysis data as JSON."""
    analysis = DomainAnalysis.query.get_or_404(analysis_id)
    return jsonify(analysis.to_dict())

@app.errorhandler(404)
def not_found_error(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    flash('An internal error occurred. Please try again.', 'danger')
    return render_template('index.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
