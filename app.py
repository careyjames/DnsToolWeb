import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for
from dns_analyzer import DNSAnalyzer

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dns-tool-secret-key")

# Initialize DNS analyzer
dns_analyzer = DNSAnalyzer()

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
