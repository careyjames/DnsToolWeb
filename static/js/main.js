if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(function() {}); // NOSONAR
}

function startStatusCycle(overlayEl) {
    var timerEl = document.getElementById('loadingTimer');
    var noteEl = document.getElementById('loadingNote');
    var startTime = Date.now();

    if (timerEl) {
        setInterval(function() {
            var elapsed = Math.floor((Date.now() - startTime) / 1000);
            timerEl.textContent = elapsed + 's';
        }, 1000);
    }
    if (noteEl) {
        setTimeout(function() {
            noteEl.style.opacity = '1';
        }, 6000);
    }

    var phases = overlayEl.querySelectorAll('.scan-phase');
    if (phases.length === 0) return;

    var completed = 0;
    phases.forEach(function(phase, idx) {
        var delay = parseInt(phase.dataset.delay, 10) || 0;
        setTimeout(function() {
            phase.classList.add('visible', 'active-phase');
        }, delay);

        var doneDelay = delay + 1800 + Math.random() * 1200;
        if (idx === phases.length - 1) {
            return;
        }
        setTimeout(function() {
            phase.classList.remove('active-phase');
            phase.classList.add('done');
            var icon = phase.querySelector('.scan-icon');
            if (icon) {
                icon.className = 'fas fa-check-circle scan-icon';
            }
            completed++;
        }, doneDelay);
    });
}

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
    const hasNonAscii = /[^\u0020-\u007F]/.test(d);
    if (!hasNonAscii) {
        for (const label of labels) {
            if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)) return false;
        }
    }
    return true;
}

function resetCopyBtn(btn) {
    btn.innerHTML = '<i class="fas fa-copy"></i>';
    btn.classList.remove('copied');
}

function handleCopyResult(btn, success) {
    btn.innerHTML = success ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>';
    if (success) btn.classList.add('copied');
    setTimeout(function() { resetCopyBtn(btn); }, 1500);
}

function createCopyHandler(codeBlock, btn) {
    return function(e) {
        e.stopPropagation();
        let copyText = '';
        codeBlock.childNodes.forEach(function(node) {
            if (node !== btn && !node.classList?.contains('copy-btn')) {
                copyText += node.textContent;
            }
        });
        copyText = copyText.trim();

        navigator.clipboard.writeText(copyText).then(
            function() { handleCopyResult(btn, true); }
        ).catch(
            function() { handleCopyResult(btn, false); }
        );
    };
}

document.addEventListener('DOMContentLoaded', function() {
    const domainForm = document.getElementById('domainForm');
    const domainInput = document.getElementById('domain');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (domainForm && domainInput && analyzeBtn) {
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
            analyzeBtn.textContent = '';
            const spinner = document.createElement('i');
            spinner.className = 'fas fa-spinner fa-spin me-2';
            analyzeBtn.appendChild(spinner);
            analyzeBtn.appendChild(document.createTextNode('Analyzing...'));
            analyzeBtn.disabled = true;
            document.body.classList.add('loading');
        });
        
        domainInput.addEventListener('focus', function() {
            this.classList.remove('is-invalid');
        });
    }
    
    document.querySelectorAll('.alert-dismissible:not(.alert-persistent)').forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 5000);
    });

    document.querySelectorAll('.alert-dismissible .btn-close').forEach(function(btn) {
        btn.addEventListener('click', function() {
            const alertEl = btn.closest('.alert');
            if (alertEl) {
                try {
                    const bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
                    bsAlert.close();
                } catch (e) {
                    console.warn('Bootstrap alert fallback:', e.message);
                    alertEl.classList.remove('show');
                    alertEl.addEventListener('transitionend', function() { alertEl.remove(); });
                    setTimeout(function() { alertEl.remove(); }, 300);
                }
            }
        });
    });
    
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.href.substring(this.href.indexOf('#')));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    document.querySelectorAll('.code-block').forEach(function(codeBlock) {
        codeBlock.style.cursor = 'pointer';
        codeBlock.title = 'Click to copy';

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'copy-btn';
        btn.setAttribute('aria-label', 'Copy to clipboard');
        btn.innerHTML = '<i class="fas fa-copy"></i>';
        codeBlock.appendChild(btn);

        const doCopy = createCopyHandler(codeBlock, btn);
        btn.addEventListener('click', doCopy);
        codeBlock.addEventListener('click', doCopy);
    });
});

const allFixesCollapse = document.getElementById('allFixesCollapse');
if (allFixesCollapse) {
    const toggleBtn = document.querySelector('[data-bs-target="#allFixesCollapse"]');
    if (toggleBtn) {
        const originalNodes = Array.from(toggleBtn.childNodes).map(function(node) {
            return node.cloneNode(true);
        });
        allFixesCollapse.addEventListener('shown.bs.collapse', function() {
            toggleBtn.textContent = '';
            const icon = document.createElement('i');
            icon.className = 'fas fa-chevron-up me-1';
            toggleBtn.appendChild(icon);
            toggleBtn.appendChild(document.createTextNode('Show fewer'));
        });
        allFixesCollapse.addEventListener('hidden.bs.collapse', function() {
            toggleBtn.textContent = '';
            originalNodes.forEach(function(node) {
                toggleBtn.appendChild(node.cloneNode(true));
            });
        });
    }
}
