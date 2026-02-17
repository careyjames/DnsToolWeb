if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(function() {}); // NOSONAR
}

globalThis.addEventListener('pageshow', function(e) {
    if (e.persisted) {
        document.querySelectorAll('.loading-overlay').forEach(function(overlay) {
            overlay.classList.remove('is-active');
        });
        document.body.classList.remove('loading');
        var reanalyzeBtn = document.getElementById('reanalyzeBtn');
        if (reanalyzeBtn && !reanalyzeBtn.classList.contains('disabled')) {
            reanalyzeBtn.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Re-analyze';
        }
        var analyzeBtn = document.getElementById('analyzeBtn');
        if (analyzeBtn) {
            analyzeBtn.innerHTML = '<i class="fas fa-search me-1"></i> Analyze';
            analyzeBtn.disabled = false;
        }
        document.querySelectorAll('.history-view-btn,.history-reanalyze-btn').forEach(function(b) {
            b.classList.remove('disabled');
            b.removeAttribute('aria-disabled');
        });
    }
});

function showOverlay(overlay) {
    if (!overlay) return;
    overlay.classList.add('is-active');
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            overlay.querySelectorAll('.loading-spinner, .loading-spinner i, .loading-dots span').forEach(function(el) {
                var anim = getComputedStyle(el).animationName;
                if (anim && anim !== 'none') {
                    el.style.animation = 'none';
                    void el.offsetWidth; // NOSONAR — Safari reflow
                    el.style.animation = '';
                }
            });
        });
    });
}

function startStatusCycle(overlayEl) {
    const timerEl = document.getElementById('loadingTimer') || overlayEl.querySelector('.loading-elapsed span');
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
            noteEl.classList.add('u-opacity-visible');
        }, 6000);
    }

    const phases = overlayEl.querySelectorAll('.scan-phase');
    if (phases.length === 0) return;

    let completed = 0;
    phases.forEach(function(phase, idx) {
        const delay = Number.parseInt(phase.dataset.delay, 10) || 0;
        setTimeout(function() {
            phase.classList.add('visible', 'active-phase');
        }, delay);

        const doneDelay = delay + 1800 + Math.random() * 1200; // NOSONAR — animation timing, not cryptographic
        if (idx === phases.length - 1) {
            return;
        }
        setTimeout(function() {
            phase.classList.remove('active-phase');
            phase.classList.add('done');
            var icon = phase.querySelector('.scan-icon');
            if (icon) {
                icon.classList.remove('fa-circle-notch', 'fa-spin', 'scan-pending');
                void icon.offsetWidth; // NOSONAR — Safari reflow trigger for ::before content swap
                icon.classList.add('fa-check-circle');
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
                showOverlay(overlay);
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
    
    document.querySelectorAll('a[href^="/analyze?domain="]').forEach(function(link) {
        if (link.id === 'reanalyzeBtn') return;
        link.addEventListener('click', function(e) {
            e.preventDefault();
            var overlay = document.getElementById('loadingOverlay');
            var loadingDomain = document.getElementById('loadingDomain');
            var url = new URL(link.href, globalThis.location.origin);
            var domain = url.searchParams.get('domain') || '';
            if (overlay) {
                if (loadingDomain) loadingDomain.textContent = domain;
                showOverlay(overlay);
                startStatusCycle(overlay);
            }
            document.body.classList.add('loading');
            requestAnimationFrame(function() { globalThis.location.href = link.href; });
        });
    });

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
        codeBlock.classList.add('u-pointer');
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

function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function loadDNSHistory(domain) {
    const btn = document.getElementById('dns-history-btn');
    if (!btn) return;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Loading history\u2026';

    fetch('/api/dns-history?domain=' + encodeURIComponent(domain))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data || data.status === 'unavailable' || data.status === 'error' || !data.available) {
                btn.closest('.dns-history-load-wrapper').classList.add('d-none');
                return;
            }
            const section = document.getElementById('dns-history-section');
            const body = document.getElementById('dns-history-body');
            const source = document.getElementById('dns-history-source');
            if (!section || !body) return;

            source.textContent = 'Source: ' + (data.source || 'SecurityTrails');

            var changes = data.changes || [];
            body.textContent = '';
            if (changes.length === 0) {
                var p = document.createElement('p');
                p.className = 'text-muted mb-0';
                var ico = document.createElement('i');
                ico.className = 'fas fa-check-circle text-success me-1';
                p.appendChild(ico);
                p.appendChild(document.createTextNode('No DNS record changes detected in available history. A, AAAA, MX, and NS records for this domain have remained stable.'));
                body.appendChild(p);
            } else {
                var wrap = document.createElement('div');
                wrap.className = 'table-responsive';
                var table = document.createElement('table');
                table.className = 'table table-sm table-striped mb-0';
                var thead = document.createElement('thead');
                var headRow = document.createElement('tr');
                var headers = [
                    {text: 'Date', cls: 'u-w-80px'}, {text: 'Type', cls: 'u-w-60px'},
                    {text: 'Action', cls: 'u-w-70px'}, {text: 'Value'}, {text: 'Organization'}, {text: 'Timeline'}
                ];
                headers.forEach(function(h) {
                    var th = document.createElement('th');
                    if (h.cls) th.className = h.cls;
                    th.textContent = h.text;
                    headRow.appendChild(th);
                });
                thead.appendChild(headRow);
                table.appendChild(thead);
                var tbody = document.createElement('tbody');
                changes.forEach(function(ch) {
                    var typeColor = 'secondary';
                    if (ch.record_type === 'A' || ch.record_type === 'AAAA') {
                        typeColor = 'primary';
                    } else if (ch.record_type === 'MX') {
                        typeColor = 'success';
                    } else if (ch.record_type === 'NS') {
                        typeColor = 'info';
                    }
                    var tr = document.createElement('tr');

                    var tdDate = document.createElement('td');
                    var codeDate = document.createElement('code');
                    codeDate.className = 'text-muted u-fs-080em';
                    codeDate.textContent = ch.date || '';
                    tdDate.appendChild(codeDate);

                    var tdType = document.createElement('td');
                    var badgeType = document.createElement('span');
                    badgeType.className = 'badge bg-' + typeColor;
                    badgeType.textContent = ch.record_type || '';
                    tdType.appendChild(badgeType);

                    var tdAction = document.createElement('td');
                    var actionSpan = document.createElement('span');
                    var actionIcon = document.createElement('i');
                    if (ch.action === 'added') {
                        actionSpan.className = 'text-success';
                        actionIcon.className = 'fas fa-plus-circle me-1';
                        actionSpan.appendChild(actionIcon);
                        actionSpan.appendChild(document.createTextNode('Added'));
                    } else {
                        actionSpan.className = 'text-danger';
                        actionIcon.className = 'fas fa-minus-circle me-1';
                        actionSpan.appendChild(actionIcon);
                        actionSpan.appendChild(document.createTextNode('Removed'));
                    }
                    tdAction.appendChild(actionSpan);

                    var tdValue = document.createElement('td');
                    var codeValue = document.createElement('code');
                    codeValue.className = 'u-fs-085em';
                    codeValue.textContent = ch.value || '';
                    tdValue.appendChild(codeValue);

                    var tdOrg = document.createElement('td');
                    var spanOrg = document.createElement('span');
                    spanOrg.className = 'text-muted';
                    spanOrg.textContent = ch.org || '\u2014';
                    tdOrg.appendChild(spanOrg);

                    var tdDesc = document.createElement('td');
                    var spanDesc = document.createElement('span');
                    spanDesc.className = 'text-muted u-fs-085em';
                    spanDesc.textContent = ch.description || '';
                    tdDesc.appendChild(spanDesc);

                    tr.appendChild(tdDate);
                    tr.appendChild(tdType);
                    tr.appendChild(tdAction);
                    tr.appendChild(tdValue);
                    tr.appendChild(tdOrg);
                    tr.appendChild(tdDesc);
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                wrap.appendChild(table);
                body.appendChild(wrap);
            }

            btn.closest('.dns-history-load-wrapper').classList.add('d-none');
            section.classList.remove('d-none');
        })
        .catch(function() {
            btn.closest('.dns-history-load-wrapper').classList.add('d-none');
        });
}
