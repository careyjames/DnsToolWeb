document.addEventListener('DOMContentLoaded', function() {
    const domainForm = document.getElementById('domainForm');
    const domainInput = document.getElementById('domain');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (domainForm && domainInput && analyzeBtn) {
        // Domain validation regex
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
        
        // Real-time validation
        domainInput.addEventListener('input', function() {
            const domain = this.value.trim();
            const isValid = domain === '' || domainRegex.test(domain);
            
            if (domain && !isValid) {
                this.classList.add('is-invalid');
                analyzeBtn.disabled = true;
            } else {
                this.classList.remove('is-invalid');
                analyzeBtn.disabled = false;
            }
        });
        
        // Form submission handling
        domainForm.addEventListener('submit', function(e) {
            const domain = domainInput.value.trim();
            
            if (!domain) {
                e.preventDefault();
                domainInput.classList.add('is-invalid');
                return;
            }
            
            if (!domainRegex.test(domain)) {
                e.preventDefault();
                domainInput.classList.add('is-invalid');
                return;
            }
            
            // Show loading overlay
            const overlay = document.getElementById('loadingOverlay');
            const loadingDomain = document.getElementById('loadingDomain');
            if (overlay) {
                if (loadingDomain) {
                    loadingDomain.textContent = domain;
                }
                overlay.style.display = 'flex';
                if (typeof window.startLoadingMessages === 'function') {
                    window.startLoadingMessages();
                }
            }
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
            analyzeBtn.disabled = true;
            document.body.classList.add('loading');
        });
        
        // Clear validation on focus
        domainInput.addEventListener('focus', function() {
            this.classList.remove('is-invalid');
        });
        
        // Handle Enter key - use requestSubmit for proper form submission
        domainInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (domainForm.requestSubmit) {
                    domainForm.requestSubmit();
                } else {
                    analyzeBtn.click();
                }
            }
        });
    }
    
    // Auto-dismiss flash message alerts after 5 seconds (not Verdict alerts)
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Copy code blocks to clipboard
    document.querySelectorAll('.code-block').forEach(function(codeBlock) {
        codeBlock.style.cursor = 'pointer';
        codeBlock.title = 'Click to copy';
        
        codeBlock.addEventListener('click', function() {
            navigator.clipboard.writeText(this.textContent).then(function() {
                // Show temporary feedback
                const originalText = codeBlock.textContent;
                const originalBg = codeBlock.style.backgroundColor;
                
                codeBlock.style.backgroundColor = 'var(--bs-success)';
                codeBlock.style.transition = 'background-color 0.2s';
                
                setTimeout(function() {
                    codeBlock.style.backgroundColor = originalBg;
                }, 200);
            }).catch(function() {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = codeBlock.textContent;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            });
        });
    });
});
