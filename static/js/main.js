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
        
        // Form submission handling - use fetch to keep page alive for animations
        domainForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Normalize to lowercase (domains are case-insensitive)
            var domain = domainInput.value.trim().toLowerCase();
            domainInput.value = domain; // Update the input to show normalized value
            
            if (!domain) {
                domainInput.classList.add('is-invalid');
                return;
            }
            
            if (!domainRegex.test(domain)) {
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
            
            // Use fetch to submit - keeps page alive for Safari
            var formData = new FormData();
            formData.append('domain', domain);
            
            fetch('/analyze', {
                method: 'POST',
                body: formData,
                redirect: 'follow'
            })
            .then(function(response) {
                // Get the HTML and replace the page
                return response.text().then(function(html) {
                    // Write the HTML to the current document
                    document.open();
                    document.write(html);
                    document.close();
                    // Update the URL in browser history
                    if (response.url && response.url !== window.location.href) {
                        window.history.pushState({}, '', response.url);
                    }
                });
            })
            .catch(function() {
                // Fallback: navigate directly
                window.location.href = '/analyze?domain=' + encodeURIComponent(domain);
            });
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
