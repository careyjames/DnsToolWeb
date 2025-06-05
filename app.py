import os
import logging
import time
from datetime import datetime, date
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import JSON
from dns_analyzer import DNSAnalyzer

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dns-tool-secret-key")

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if database_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
else:
    # Fallback for development
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dns_analysis.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Initialize DNS analyzer
dns_analyzer = DNSAnalyzer()

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

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    """Main page with domain input form."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze DNS records for the submitted domain."""
    domain = request.form.get('domain', '').strip()
    
    if not domain:
        flash('Please enter a domain name.', 'danger')
        return redirect(url_for('index'))
    
    # Validate domain
    if not dns_analyzer.validate_domain(domain):
        flash(f'Invalid domain name: {domain}', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Convert to ASCII for IDNA domains
        ascii_domain = dns_analyzer.domain_to_ascii(domain)
        
        # Perform DNS analysis
        results = dns_analyzer.analyze_domain(ascii_domain)
        
        return render_template('results.html', 
                             domain=domain, 
                             ascii_domain=ascii_domain,
                             results=results)
        
    except Exception as e:
        logging.error(f"Error analyzing domain {domain}: {e}")
        flash(f'Error analyzing domain: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    flash('An internal error occurred. Please try again.', 'danger')
    return render_template('index.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
