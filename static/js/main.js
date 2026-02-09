if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(function() {}); // NOSONAR
}

function startStatusCycle(overlayEl) {
    const statusDiv = overlayEl.querySelector('.loading-status');
    if (!statusDiv) return;
    const spans = statusDiv.querySelectorAll('span');
    if (spans.length === 0) return;
    let current = 0;
    spans.forEach(function(s) { s.classList.remove('active'); });
    spans[0].classList.add('active');
    setInterval(function() {
        spans[current].classList.remove('active');
        current = (current + 1) % spans.length;
        spans[current].classList.add('active');
    }, 2500);

    const timerEl = document.getElementById('loadingTimer');
    const noteEl = document.getElementById('loadingNote');
    const startTime = Date.now();
    if (timerEl) {
        setInterval(function() {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            timerEl.textContent = elapsed + 's';
        }, 1000);
    }
    if (noteEl) {
        setTimeout(function() {
            noteEl.style.opacity = '1';
        }, 4000);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const domainForm = document.getElementById('domainForm');
    const domainInput = document.getElementById('domain');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (domainForm && domainInput && analyzeBtn) {
        function isValidDomain(domain) {
            if (!domain) return false;
            const d = domain.replace(/\.$/, '');
            if (d.length > 253 || d.length === 0) return false;
            const labels = d.split('.');
            if (labels.length < 2) return false;
            for (const label of labels) {
                if (label.length === 0 || label.length > 63) return false;
                if (label.startsWith('-') || label.endsWith('-')) return false;
            }
            const tld = labels[labels.length - 1];
            if (/^\d+$/.test(tld)) return false;
            const hasNonAscii = /[^\u0000-\u007F]/.test(d);
            if (!hasNonAscii) {
                for (const label of labels) {
                    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)) return false;
                }
            }
            return true;
        }

        domainInput.addEventListener('input', function() {
            const domain = this.value.trim();
            const isValid = domain === '' || isValidDomain(domain);

            if (domain && !isValid) {
                this.classList.add('is-invalid');
                analyzeBtn.disabled = true;
            } else {
                this.classList.remove('is-invalid');
                analyzeBtn.disabled = false;
            }
        });
        
        domainForm.addEventListener('submit', function(e) {
            const domain = domainInput.value.trim().toLowerCase();
            domainInput.value = domain;
            
            if (!domain) {
                e.preventDefault();
                domainInput.classList.add('is-invalid');
                return;
            }
            
            if (!isValidDomain(domain)) {
                e.preventDefault();
                domainInput.classList.add('is-invalid');
                return;
            }
            
            const overlay = document.getElementById('loadingOverlay');
            const loadingDomain = document.getElementById('loadingDomain');
            if (overlay) {
                if (loadingDomain) {
                    loadingDomain.textContent = domain;
                }
                overlay.classList.remove('d-none');
                startStatusCycle(overlay);
            }
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
            analyzeBtn.disabled = true;
            document.body.classList.add('loading');
        });
        
        // Clear validation on focus
        domainInput.addEventListener('focus', function() {
            this.classList.remove('is-invalid');
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

        const icon = document.createElement('i');
        icon.className = 'fas fa-copy copy-icon';
        codeBlock.appendChild(icon);
        
        codeBlock.addEventListener('click', function() {
            let copyText = '';
            codeBlock.childNodes.forEach(function(node) {
                if (!node.classList || !node.classList.contains('copy-icon')) {
                    copyText += node.textContent;
                }
            });
            copyText = copyText.trim();

            navigator.clipboard.writeText(copyText).then(function() {
                icon.className = 'fas fa-check copy-icon';
                icon.style.color = 'var(--bs-success)';

                setTimeout(function() {
                    icon.className = 'fas fa-copy copy-icon';
                    icon.style.color = '';
                }, 1500);
            }).catch(function() {
                icon.className = 'fas fa-times copy-icon';
                icon.style.color = 'var(--bs-warning)';
                setTimeout(function() {
                    icon.className = 'fas fa-copy copy-icon';
                    icon.style.color = '';
                }, 1500);
            });
        });
    });
});
