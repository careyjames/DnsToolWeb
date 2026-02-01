# DNS Analysis Tool

## Overview

A web-based DNS intelligence tool that provides comprehensive domain record analysis, email security validation (SPF, DMARC, DKIM), and DNS security intelligence reports. The application allows users to analyze domains, view DNS records, check email security configurations, and maintain a history of past analyses with usage statistics.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Framework
- **Flask** serves as the web framework, handling HTTP requests and rendering templates
- **SQLAlchemy** provides ORM functionality with a declarative base pattern
- **PostgreSQL** is used as the database for storing domain analysis results (Replit-managed, reliable)

### Core Components

**Application Entry Points:**
- `main.py` - Simple entry point that imports the Flask app
- `app.py` - Main application file containing Flask configuration, database models, and route handlers

**DNS Analysis Engine:**
- `dns_analyzer.py` - Core DNS analysis logic using the `dnspython` library
- Handles domain validation, IDNA encoding for internationalized domains
- Queries DNS records and performs email security analysis (SPF, DMARC)
- Uses external DNS resolvers (default: 1.1.1.1) with configurable timeout
- Fetches IANA RDAP data for domain registry lookups
- SMTP Transport Verification: Checks MX server STARTTLS support, TLS version, cipher strength, and certificate validity
- DNS Infrastructure Analysis: Detects enterprise-grade DNS providers (Cloudflare, AWS, Google, Akamai, Azure) and explains alternative security measures when DNSSEC is not enabled

**Data Model:**
- `DomainAnalysis` model stores analysis results with JSON fields for flexible record storage
- Tracks basic DNS records, authoritative records, SPF/DMARC status and policies

### Frontend Architecture
- Server-rendered HTML templates using Jinja2
- Bootstrap dark theme for styling (loaded from CDN)
- Font Awesome icons for UI elements
- Custom CSS: `static/css/custom.css` (source) → `static/css/custom.min.css` (minified, used in production)
- Client-side JavaScript in `static/js/main.js` for form validation and UX enhancements
- CSS Minification: Run `python3 -c "import cssmin; ..."` to regenerate minified CSS after changes

**Pages:**
- Index (home) - Domain input form
- Results - Detailed DNS analysis display
- History - List of past analyses
- Statistics - Usage trends and metrics

### Design Patterns
- MVC-style separation with Flask routes as controllers, SQLAlchemy models, and Jinja2 templates as views
- Singleton pattern for the DNSAnalyzer instance
- JSON columns in PostgreSQL for storing variable-structure DNS record data

## External Dependencies

### Python Packages
- **Flask** - Web framework
- **Flask-SQLAlchemy** - Database ORM integration
- **dnspython** - DNS query library for record lookups
- **requests** - HTTP client for external API calls (IANA RDAP)
- **idna** (optional) - Internationalized domain name encoding

### External Services
- **Cloudflare DNS (1.1.1.1)** - Default DNS resolver for queries
- **IANA RDAP** - Registry data for domain information lookups

### Frontend CDN Resources
- Bootstrap dark theme CSS
- Font Awesome icons

### Database
- PostgreSQL (Replit-managed via DATABASE_URL environment variable)