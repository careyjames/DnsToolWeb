# Drift Engine — Roadmap & Design

## Philosophy

The drift engine extends DNS Tool's observation-based analysis from a point-in-time report into a longitudinal record. Every scan is a live, fresh observation (TTL=0, multi-resolver). The drift engine **never replaces or caches live results**. It records what was observed and detects when observations change over time.

This is our own intelligence — not SecurityTrails, not a third-party feed. We observed it, we recorded it, we detected the change.

## Architecture Principles

1. **Live results are sacred.** The analysis path (`AnalyzeDomain` → render `results.html`) is never altered. Snapshots are a side effect of analysis, stored after the live results are delivered.
2. **Conservative storage.** We store lean posture hashes for drift comparison, not redundant copies of full results. The existing `full_results` JSON in `domain_analyses` is the detailed record.
3. **Canonical hashing.** DNS records are normalized (sorted, lowercased, whitespace-stripped) before hashing so that cosmetic differences don't trigger false drift alerts.
4. **No false alarms.** Drift detection compares posture hashes. A change in presentation (e.g., record ordering from a DNS provider) should not register as drift.

---

## Phase 1: Foundation (Current Session)

### 1A. Posture Hash Column

Add a `posture_hash` column (VARCHAR 64, SHA-256 hex) to the existing `domain_analyses` table. This hash represents the canonical posture fingerprint at the time of analysis.

**What gets hashed (the "posture vector"):**
- SPF: status, record text (sorted)
- DMARC: status, policy, record text
- DKIM: status, discovered selectors (sorted)
- MTA-STS: status, mode
- TLS-RPT: status
- BIMI: status
- DANE/TLSA: status, has_dane flag, record count
- CAA: status, issue/issuewild tags (sorted)
- DNSSEC: status, validated flag
- Mail posture: label
- MX records: sorted list of MX hosts
- NS records: sorted list of nameservers

**Not included in posture hash (volatile/cosmetic):**
- TTL values (change frequently, not posture-relevant)
- Analysis duration
- Country of requester
- CT subdomains (discovery set varies)
- ASN details (informational, not posture)
- Timestamps

### 1B. Canonical Hashing Utility

New file: `go-server/internal/analyzer/posture_hash.go`

- `CanonicalPostureHash(results map[string]any) string` — extracts posture vector from analysis results, normalizes, sorts, and returns SHA-256 hex digest.
- Deterministic: same DNS posture → same hash, regardless of query order or formatting.
- Unit tested: `posture_hash_test.go` with known inputs/outputs.

### 1C. Wire Into Save Path

In `analysis.go` `saveAnalysis()`, compute posture hash from results and store it alongside the analysis. This is a one-line addition after the existing save logic — no changes to the live analysis path.

### 1D. Query: Get Previous Hash

New sqlc query: `GetPreviousPostureHash` — given a domain, return the posture_hash from the most recent prior successful analysis. This enables the handler to compare current vs. previous in a future phase.

---

## Phase 2: Drift Detection (Next Session)

### 2A. Compare Current vs. Previous

After computing the current posture hash, query the previous hash for the same domain. If they differ, flag `drift_detected: true` in the results passed to the template.

### 2B. Drift Detail Extraction

When drift is detected, compute a structured diff:
- Which posture fields changed (e.g., "DMARC policy changed from none to reject")
- Severity classification (critical: SPF/DMARC degradation; info: new CAA tag added)
- Previous vs. current values for changed fields

### 2C. Results Page Integration

Add a drift section to `results.html`:
- "Posture Change Detected" banner (only when drift exists)
- Concise list of what changed with severity indicators
- Link to previous analysis for comparison
- Clear label: "Compared against your previous observation on [date]"

---

## Phase 3: Timeline UI (Future)

### 3A. Domain Posture Timeline

New page: `/posture-timeline?domain=example.com`
- Chronological list of all observations for a domain
- Posture hash change markers (visual timeline)
- Score/grade progression over time
- Expandable detail for each observation

### 3B. Posture Trend Visualization

- Simple chart showing posture score over time
- Protocol-level status progression (SPF: none → softfail → fail → pass)
- Key events annotated on timeline

---

## Phase 4: Alerting (Future)

### 4A. Drift Notification Framework

- Webhook support for posture changes
- Email alerts (optional, requires SMTP config)
- Configurable sensitivity (alert on any change vs. only degradations)
- Rate limiting to prevent alert storms

### 4B. Scheduled Monitoring

- Periodic re-scan of watched domains
- Configurable scan intervals
- Dashboard of monitored domains with current posture status

---

## Storage Considerations

### Current approach (Phase 1):
- `posture_hash` is 64 bytes per row — negligible storage cost
- No new tables required — extends existing `domain_analyses`
- Full results already stored as JSON — no duplication

### Future considerations:
- Retention policy: keep detailed `full_results` for N days, then retain only posture hash + key fields
- Archival: compress old `full_results` JSON or move to cold storage
- Index: add index on `(domain, posture_hash, created_at)` for drift queries

---

## Testing Strategy

- Golden rule test: `TestGoldenRulePostureHashDeterministic` — same input → same hash
- Golden rule test: `TestGoldenRulePostureHashChangesOnDrift` — different SPF → different hash
- Integration: verify posture_hash is stored and retrievable
- Regression: all existing 50 golden rule sub-tests must continue to pass

---

## Version History

| Date | Phase | Status | Notes |
|------|-------|--------|-------|
| Feb 15, 2026 | 1 (Foundation) | Complete | Schema + hashing + save path + 10 golden rule tests |

---

## Key Decisions

1. **Single table, not a new table.** Adding `posture_hash` to `domain_analyses` keeps the schema simple. Each row is already a snapshot — adding a hash column makes it drift-comparable without architectural changes.

2. **SHA-256 for hashing.** Standard, deterministic, collision-resistant. 64-char hex string fits in a VARCHAR(64).

3. **Posture vector scope.** We hash security-relevant protocol states, not cosmetic/volatile fields. This prevents false drift signals from TTL changes, ASN updates, or CT log variance.

4. **No caching of results.** The drift engine observes and records but never serves stale data. Live analysis always runs fresh.
