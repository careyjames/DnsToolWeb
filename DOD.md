# Definition of Done

Every change must satisfy this checklist before it ships.

---

## Code Quality

- [ ] Format passes (`gofmt`)
- [ ] Lint passes (`go vet`)
- [ ] Typecheck passes (compiles cleanly)
- [ ] All tests pass (`go test ./...`)
- [ ] Golden rules pass (`go test -run TestGoldenRule ./internal/analyzer/ -v`)
- [ ] No new high/critical findings from code quality scanners
- [ ] Diffs are minimal — smallest change that solves the problem

## Security

- [ ] No secrets in code, logs, or docs
- [ ] No debug endpoints or test backdoors
- [ ] No silent failures — errors are structured and surfaced
- [ ] SSRF, injection, and authz boundaries reviewed for any change touching external input
- [ ] Secrets managed through environment variables only, never hardcoded

## Testing

- [ ] Add or adjust tests for every behavior change
- [ ] Golden rule test added if change affects detection logic or scoring
- [ ] Edge cases covered — not just the happy path

## Documentation

- [ ] replit.md updated if architecture or features changed
- [ ] DOCS.md updated if user-facing behavior changed
- [ ] No proprietary intelligence exposed in public-facing docs
- [ ] Observation-based language used (never definitive claims)

## Build and Deploy

- [ ] CSS minified if changed (`npx csso`)
- [ ] JS minified if changed (`npx terser`)
- [ ] Version bumped if static assets changed (`AppVersion` in config.go)
- [ ] Go binary rebuilt and tested
- [ ] Workflow restarted and running without errors

## Quality Gates — Lighthouse, Observatory & SonarCloud (MANDATORY)

Every change must maintain or improve these scores. **Never ship a regression.**

| Tool | Category | Target | Acceptable |
|------|----------|--------|------------|
| Lighthouse | Performance | 100 | 98–100 (network variance) |
| Lighthouse | Best Practices | 100 | 100 (errors = broken UX) |
| Lighthouse | Accessibility | 100 | 100 (no excuses) |
| Lighthouse | SEO | 100 | 100 (no excuses) |
| Mozilla Observatory | Security | 130 | 130 (never go backwards) |
| SonarCloud | Reliability | A | A (zero new bugs) |
| SonarCloud | Security | A | A (zero new vulnerabilities) |
| SonarCloud | Maintainability | A | A (zero new code smells) |

- [ ] Lighthouse Performance ≥ 98 (preferably 100)
- [ ] Lighthouse Best Practices = 100
- [ ] Lighthouse Accessibility = 100
- [ ] Lighthouse SEO = 100
- [ ] Mozilla Observatory ≥ 130
- [ ] SonarCloud Quality Gate passes (Reliability A, Security A, Maintainability A)
- [ ] No new bugs, vulnerabilities, or code smells introduced
- [ ] Security hotspots reviewed (not left unreviewed)

**Rules:**
1. Best Practices < 100 means a real error exists that affects user experience — fix it.
2. Accessibility < 100 means broken markup — missing labels, contrast, ARIA — fix it.
3. SEO < 100 means missing metadata, structural issues — fix it.
4. Performance 98–100 is acceptable due to network variance; consistent 100 is the goal.
5. Observatory score must never decrease. Security posture only moves forward.
6. SonarCloud A-rating is non-negotiable. Code quality is foundational, not retroactive.
7. **Test URL**: `https://pagespeed.web.dev/` against `https://dnstool.it-help.tech`
8. **Observatory URL**: `https://observatory.mozilla.org/` against `dnstool.it-help.tech`
9. **SonarCloud**: Enforced via CI on GitHub (`sonarcloud.yml`). Quality Gate must pass before merge.

## Development Process — Research First, Build Correctly

The anti-pattern is: build fast, get an idea working, then clean up. The correct process is:

- [ ] **Research before coding** — find the best-practices path, cite RFCs or authority sources
- [ ] **Design before implementing** — identify boundaries, error paths, data flows
- [ ] **Let tests guide** — write or update tests first, then implement to pass them
- [ ] **Quality gates are guardrails, not afterthoughts** — check them during development, not after
- [ ] **Smallest correct change** — not the fastest change, not the most impressive change

**The tests, quality gates, and documentation exist to prevent rework. Use them.**

## Standards

- [ ] Every conclusion is RFC-cited or authority-backed
- [ ] Every detection is independently verifiable with standard commands
- [ ] No clever tricks — boring, explicit, testable code
- [ ] No new dependencies without justification
- [ ] If something is an assumption, it is labeled as such

## Public Repo Safety

- [ ] No analyzer logic details in public docs
- [ ] No provider database contents exposed
- [ ] No scoring algorithms or remediation text revealed
- [ ] No schema keys or internal data structures listed
- [ ] Legacy source code not present in tracked files
