# Legacy Python/Flask Codebase — Archive Record

## Status: RETIRED
**Retirement Date:** February 2026
**Replaced By:** Go/Gin implementation in `go-server/`
**Final Python Version:** v26.10.88

---

## Why This Archive Exists

The DNS Tool was originally built in Python using Flask, SQLAlchemy, and
dnspython. In early 2026 the entire application was rewritten in Go (Gin
framework, pgx/sqlc, miekg/dns) for improved performance, concurrency,
and maintainability.

## Source Code Removed

Legacy Python source code, test suites, and migration files were removed
from the public repository to protect proprietary intelligence. The file
index below documents what existed for historical reference only.

The active, maintained codebase is at `go-server/`. See `replit.md` for
current architecture documentation.

## Why It Was Replaced

| Concern | Python/Flask | Go/Gin |
|---------|-------------|--------|
| Concurrency | Thread pool, GIL-limited | Native goroutines |
| DNS queries | dnspython (pure Python) | miekg/dns (low-level, fast) |
| Type safety | Runtime checks only | Compile-time via sqlc, strong typing |
| Binary deployment | Interpreter + pip deps | Single static binary |
| Cold start | ~2-3 s (imports) | ~50 ms |

## Historical File Index

The following files existed in the legacy Python codebase. Source code
has been removed from the public repository.

### Application Core
| File | Lines | Purpose |
|------|-------|---------|
| `app.py` | 1,580 | Flask app factory, routes, middleware |
| `dns_analyzer.py` | 5,400 | Core analysis engine |
| `main.py` | 1 | WSGI entry point |

### Test Suite
| File | Purpose |
|------|---------|
| `test_dns_analyzer.py` | Unit tests |
| `test_integration.py` | Integration tests |
| `test_edge_cases.py` | Edge-case coverage |
