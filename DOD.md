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
