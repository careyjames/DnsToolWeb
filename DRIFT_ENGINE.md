# Drift Engine — Foundation

## Status

The drift engine extends DNS Tool's observation-based analysis from point-in-time reports into longitudinal monitoring. Every scan generates a canonical posture hash (SHA-256) that fingerprints the domain's security posture at the time of analysis. When a domain is re-analyzed, the current hash is compared against the previous observation to detect posture drift.

### Implemented (Phase 1–2)

- **Canonical posture hashing** (`posture_hash.go`): Deterministic SHA-256 of normalized security posture vector (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, DANE, CAA, DNSSEC, mail posture, MX, NS). Order-independent — sorted before hashing to prevent false drift from DNS provider record reordering.
- **Database persistence**: `posture_hash VARCHAR(64)` column on `domain_analyses`. Every successful analysis stores its posture hash.
- **Drift comparison**: Live analysis and history views compare current vs. previous posture hash. Drift detected when hashes differ.
- **Drift alert UI**: "Posture Drift Detected" banner on results page when drift is found, with hash previews and link to previous report.

### Architecture Principles

1. **Live results are sacred.** The analysis path is never altered by drift detection. Snapshots are a side effect.
2. **Conservative storage.** Lean posture hashes for comparison, not redundant copies of full results.
3. **Canonical hashing.** DNS records normalized (sorted, lowercased, whitespace-stripped) before hashing. Cosmetic differences don't trigger false drift.
4. **No false alarms.** Presentation changes (record ordering) don't register as drift.

### Roadmap

Additional drift engine capabilities (timeline visualization, alerting, scheduled monitoring) are on the roadmap. Details available under commercial license — contact licensing@it-help.tech.

---

*Full roadmap and design documentation maintained in the private repository.*
