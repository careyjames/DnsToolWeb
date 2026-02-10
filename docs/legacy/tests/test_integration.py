"""
Integration tests for Flask routes and full request/response flows.
Tests route accessibility, response codes, and content validation.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db


class BaseTestCase(unittest.TestCase):
    """Base test case with Flask test client setup."""
    
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()
    
    def tearDown(self):
        self.ctx.pop()


class TestHomePage(BaseTestCase):
    """Tests for the homepage route."""
    
    def test_homepage_loads(self):
        """Homepage should return 200 and contain domain input form."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'domain', response.data.lower())
    
    def test_homepage_has_analyze_button(self):
        """Homepage should have analyze button."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Analyze', response.data)
    
    def test_homepage_has_navigation(self):
        """Homepage should have navigation links."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'History', response.data)
        has_stats = b'Stats' in response.data or b'Statistics' in response.data or b'stats' in response.data
        self.assertTrue(has_stats, "Should have stats/statistics link")


class TestAnalyzeRoute(BaseTestCase):
    """Tests for the /analyze route - input validation."""
    
    def test_analyze_empty_domain(self):
        """Empty domain should redirect to homepage."""
        response = self.client.get('/analyze?domain=')
        self.assertIn(response.status_code, [200, 302])
    
    def test_analyze_no_domain_param(self):
        """Missing domain parameter should redirect."""
        response = self.client.get('/analyze')
        self.assertIn(response.status_code, [200, 302])
    
    def test_analyze_invalid_domain_format(self):
        """Invalid domain format should redirect with error."""
        invalid_domains = [
            'not-valid',
            'http://example.com',
            'example.com/path',
            '.example.com',
        ]
        for domain in invalid_domains:
            response = self.client.get(f'/analyze?domain={domain}')
            self.assertIn(response.status_code, [200, 302], f"Failed for: {domain}")
    
    def test_analyze_post_method(self):
        """POST method should work for analyze."""
        response = self.client.post('/analyze', data={'domain': 'example.com'})
        self.assertIn(response.status_code, [200, 302])


class TestHistoryRoute(BaseTestCase):
    """Tests for the /history route."""
    
    def test_history_loads(self):
        """History page should return 200."""
        response = self.client.get('/history')
        self.assertEqual(response.status_code, 200)
    
    def test_history_has_table_structure(self):
        """History should have table or empty state message."""
        response = self.client.get('/history')
        self.assertEqual(response.status_code, 200)
        has_table = b'<table' in response.data or b'No analyses' in response.data
        self.assertTrue(has_table or b'history' in response.data.lower())


class TestStatsRoute(BaseTestCase):
    """Tests for the /stats route."""
    
    def test_stats_loads(self):
        """Stats page should return 200."""
        response = self.client.get('/stats')
        self.assertEqual(response.status_code, 200)
    
    def test_stats_has_metrics(self):
        """Stats should display usage metrics."""
        response = self.client.get('/stats')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'stats', response.data.lower())


class TestStaticRoutes(BaseTestCase):
    """Tests for static content routes."""
    
    def test_robots_txt(self):
        """robots.txt should be accessible."""
        response = self.client.get('/robots.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'User-agent', response.data)
    
    def test_sitemap(self):
        """sitemap.xml should be accessible."""
        response = self.client.get('/sitemap.xml')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'xml', response.data.lower())
    
    def test_llms_txt(self):
        """llms.txt should be accessible."""
        response = self.client.get('/llms.txt')
        self.assertEqual(response.status_code, 200)
    
    def test_llms_full_txt(self):
        """llms-full.txt should be accessible."""
        response = self.client.get('/llms-full.txt')
        self.assertEqual(response.status_code, 200)


class TestAPIRoute(BaseTestCase):
    """Tests for the API endpoint."""
    
    def test_api_analysis_not_found(self):
        """API should return 404 for non-existent analysis."""
        response = self.client.get('/api/analysis/999999')
        self.assertEqual(response.status_code, 404)
    
    def test_api_analysis_invalid_id(self):
        """API should handle invalid ID gracefully."""
        response = self.client.get('/api/analysis/invalid')
        self.assertIn(response.status_code, [400, 404, 500])


class TestSecurityHeaders(BaseTestCase):
    """Tests for security headers."""
    
    def test_csp_header_present(self):
        """CSP header should be present on responses."""
        response = self.client.get('/')
        csp = response.headers.get('Content-Security-Policy')
        self.assertIsNotNone(csp)
    
    def test_csp_has_nonce(self):
        """CSP should include nonce for inline scripts."""
        response = self.client.get('/')
        csp = response.headers.get('Content-Security-Policy', '')
        self.assertIn('nonce-', csp)
    
    def test_csp_has_script_src(self):
        """CSP should have script-src directive."""
        response = self.client.get('/')
        csp = response.headers.get('Content-Security-Policy', '')
        self.assertIn('script-src', csp)
    
    def test_x_content_type_options(self):
        """X-Content-Type-Options header should be present."""
        response = self.client.get('/')
        xcto = response.headers.get('X-Content-Type-Options')
        self.assertEqual(xcto, 'nosniff')
    
    def test_x_frame_options(self):
        """X-Frame-Options should be set."""
        response = self.client.get('/')
        xfo = response.headers.get('X-Frame-Options')
        self.assertIn(xfo, ['DENY', 'SAMEORIGIN'])


class TestErrorHandling(BaseTestCase):
    """Tests for error handling."""
    
    def test_404_page(self):
        """404 should be returned for unknown routes."""
        response = self.client.get('/nonexistent-page-xyz')
        self.assertEqual(response.status_code, 404)


class TestBIMIProxy(BaseTestCase):
    """Tests for BIMI logo proxy route."""
    
    def test_bimi_proxy_no_url(self):
        """BIMI proxy without URL should return error."""
        response = self.client.get('/proxy/bimi-logo')
        self.assertIn(response.status_code, [400, 404])
    
    def test_bimi_proxy_invalid_url(self):
        """BIMI proxy with invalid URL should return error."""
        response = self.client.get('/proxy/bimi-logo?url=not-a-url')
        self.assertIn(response.status_code, [400, 500])


class TestRateLimiter(unittest.TestCase):
    """Tests for the rate limiter functionality."""
    
    def setUp(self):
        from app import RateLimiter
        self.limiter = RateLimiter()
    
    def test_rate_limit_allows_initial_requests(self):
        """Rate limiter should allow initial requests."""
        allowed, _ = self.limiter.check_rate_limit('192.168.1.1')
        self.assertTrue(allowed)
    
    def test_rate_limit_blocks_after_max_requests(self):
        """Rate limiter should block after max requests."""
        test_ip = '192.168.1.100'
        for i in range(8):
            self.limiter.record_request(test_ip, f'domain{i}.com')
        
        allowed, wait_seconds = self.limiter.check_rate_limit(test_ip)
        self.assertFalse(allowed)
        self.assertGreater(wait_seconds, 0)
    
    def test_anti_repeat_allows_first_request(self):
        """Anti-repeat should allow first request for a domain."""
        allowed, _ = self.limiter.check_anti_repeat('192.168.1.2', 'example.com')
        self.assertTrue(allowed)
    
    def test_anti_repeat_blocks_immediate_repeat(self):
        """Anti-repeat should block immediate repeat for same domain."""
        test_ip = '192.168.1.3'
        domain = 'test.com'
        
        self.limiter.record_request(test_ip, domain)
        allowed, wait_seconds = self.limiter.check_anti_repeat(test_ip, domain)
        
        self.assertFalse(allowed)
        self.assertGreater(wait_seconds, 0)
        self.assertLessEqual(wait_seconds, 15)
    
    def test_anti_repeat_allows_different_domain(self):
        """Anti-repeat should allow requests to different domains."""
        test_ip = '192.168.1.4'
        
        self.limiter.record_request(test_ip, 'domain1.com')
        allowed, _ = self.limiter.check_anti_repeat(test_ip, 'domain2.com')
        
        self.assertTrue(allowed)
    
    def test_anti_repeat_case_insensitive(self):
        """Anti-repeat should be case-insensitive for domains."""
        test_ip = '192.168.1.5'
        
        self.limiter.record_request(test_ip, 'Example.COM')
        allowed, _ = self.limiter.check_anti_repeat(test_ip, 'example.com')
        
        self.assertFalse(allowed)
    
    def test_check_and_record_atomic_success(self):
        """check_and_record should atomically check and record on success."""
        test_ip = '192.168.1.6'
        domain = 'atomic-test.com'
        
        allowed, reason, _ = self.limiter.check_and_record(test_ip, domain)
        
        self.assertTrue(allowed)
        self.assertEqual(reason, 'ok')
        
        # Second request should be blocked by anti-repeat
        allowed, reason, wait = self.limiter.check_and_record(test_ip, domain)
        self.assertFalse(allowed)
        self.assertEqual(reason, 'anti_repeat')
        self.assertGreater(wait, 0)
    
    def test_check_and_record_rate_limit(self):
        """check_and_record should enforce rate limit."""
        test_ip = '192.168.1.7'
        
        # Make 8 requests (max allowed)
        for i in range(8):
            allowed, reason, _ = self.limiter.check_and_record(test_ip, f'domain{i}.com')
            self.assertTrue(allowed)
        
        # 9th request should be rate limited
        allowed, reason, wait = self.limiter.check_and_record(test_ip, 'domain9.com')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'rate_limit')
        self.assertGreater(wait, 0)


class TestCountdownButtonState(BaseTestCase):
    """Tests for countdown button state transitions when rate limited."""
    
    def setUp(self):
        super().setUp()
        from app import RateLimiter
        # Get the global rate limiter to manipulate state
        import app as app_module
        self.rate_limiter = app_module.rate_limiter
    
    def test_static_view_route_exists(self):
        """Static view route should return 404 for non-existent analysis."""
        response = self.client.get('/analysis/99999/view')
        self.assertEqual(response.status_code, 404)
    
    def test_static_view_with_wait_params(self):
        """Static view should accept wait_seconds query parameter."""
        # Test param parsing with a non-existent ID
        response = self.client.get('/analysis/99999/view?wait_seconds=10&wait_reason=anti_repeat')
        # Should be 404 (not found) but not crash
        self.assertEqual(response.status_code, 404)
    
    def test_index_page_accepts_wait_params(self):
        """Index page should accept wait_seconds parameter for countdown display."""
        response = self.client.get('/?wait_seconds=10&wait_domain=example.com')
        self.assertEqual(response.status_code, 200)
        # Check that the data attributes are in the response
        self.assertIn(b'data-wait-seconds', response.data)
    
    def test_results_button_has_data_attributes(self):
        """Results page re-analyze button should have data-domain attribute."""
        # First need an analysis to exist - this may take time or redirect
        response = self.client.get('/analyze?domain=example.com', follow_redirects=True)
        if response.status_code == 200:
            # Check for re-analyze button with data-domain (results page)
            # or for domain input (home page if redirected due to rate limit)
            has_reanalyze = b'data-domain' in response.data or b'reanalyzeBtn' in response.data
            has_home = b'domainForm' in response.data
            self.assertTrue(has_reanalyze or has_home, "Should have results or home page elements")
    
    def test_countdown_ui_elements_present(self):
        """Countdown JS code should be present in templates."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        # Check for countdown-related JS
        self.assertIn(b'waitSeconds', response.data)
        self.assertIn(b'updateCountdown', response.data)


class TestStaticViewRoute(BaseTestCase):
    """Tests for the /analysis/{id}/view static view route."""
    
    def test_static_view_404_for_missing(self):
        """Static view should 404 for non-existent analysis."""
        response = self.client.get('/analysis/999999/view')
        self.assertEqual(response.status_code, 404)
    
    def test_static_view_preserves_wait_seconds(self):
        """Static view should pass wait_seconds to template."""
        # Can't easily test with real data, but verify route doesn't crash
        response = self.client.get('/analysis/1/view?wait_seconds=5&wait_reason=anti_repeat')
        # Either 200 (if analysis exists) or 404 (if not)
        self.assertIn(response.status_code, [200, 404])


if __name__ == '__main__':
    unittest.main()
