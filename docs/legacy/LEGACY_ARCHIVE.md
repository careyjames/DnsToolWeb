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

This directory preserves the legacy Python source code for historical
reference. It is **not maintained**, **not executed**, and **not part of
the build pipeline**. The authoritative codebase is `go-server/`.

## Why It Was Replaced

| Concern | Python/Flask | Go/Gin |
|---------|-------------|--------|
| Concurrency | Thread pool, GIL-limited | Native goroutines |
| DNS queries | dnspython (pure Python) | miekg/dns (low-level, fast) |
| Type safety | Runtime checks only | Compile-time via sqlc, strong typing |
| Binary deployment | Interpreter + pip deps | Single static binary |
| Cold start | ~2-3 s (imports) | ~50 ms |

## Migration Process

1. Feature parity was tracked via `tests/feature_parity_manifest.py`
   (preserved here) which enumerated every analysis capability.
2. Golden-fixture tests (`tests/test_golden.py`, `tests/golden_fixture_capture_go.py`)
   ensured output compatibility between Python and Go implementations.
3. Schema contracts (`tests/schema_contract.py`, `tests/test_schema_validation.py`)
   verified the Go server produced identical JSON structures.
4. Behavioral contracts (`tests/test_behavioral_contracts.py`) validated
   edge-case handling matched across implementations.

## Archived File Index

### Application Core (from repo root)
| File | Lines | Purpose |
|------|-------|---------|
| `src/app.py` | 1,580 | Flask app factory, routes, middleware, CSRF |
| `src/dns_analyzer.py` | 5,400 | Core DNS analysis engine |
| `src/dns_providers.py` | 371 | Provider fingerprint maps |
| `src/dns_types.py` | 188 | Type definitions and enums |
| `src/main.py` | 1 | WSGI entry point |
| `src/models.py` | 0 | SQLAlchemy models (empty — schema in app.py) |
| `src/network_telemetry.py` | 272 | Resolver health and latency tracking |
| `src/rdap_cache.py` | 95 | RDAP response caching |
| `src/remediation_guidance.py` | 516 | RFC-cited remediation text |

### Test Suite (from repo root tests/)
| File | Lines | Purpose |
|------|-------|---------|
| `tests/analyzer_interface.py` | 105 | Adapter for running Python analyzer in tests |
| `tests/feature_parity_manifest.py` | 354 | Exhaustive feature enumeration for migration |
| `tests/golden_fixture_capture.py` | 89 | Capture golden fixtures from Python |
| `tests/golden_fixture_capture_go.py` | 145 | Capture golden fixtures from Go (bridge) |
| `tests/schema_contract.py` | 538 | JSON schema contracts |
| `tests/test_behavioral_contracts.py` | 388 | Edge-case behavioral tests |
| `tests/test_dns_analyzer.py` | 621 | Unit tests for analyzer |
| `tests/test_edge_cases.py` | 799 | Comprehensive edge-case coverage |
| `tests/test_golden.py` | 704 | Golden-fixture comparison tests |
| `tests/test_integration.py` | 368 | Integration tests |
| `tests/test_schema_validation.py` | 232 | Schema validation tests |

### Database Migrations (Alembic)
| File | Purpose |
|------|---------|
| `migrations/alembic.ini` | Alembic configuration |
| `migrations/env.py` | Migration environment setup |
| `migrations/script.py.mako` | Migration template |
| `migrations/versions/` | (empty — migrations were applied in production) |

### Dependency Management
| File | Purpose |
|------|---------|
| `pyproject.toml` | Python project metadata and dependencies |

## Excluded from Archive (Reproducible Artifacts)

The following were deleted, not archived, because they are generated
artifacts that can be reproduced from the source files above:

- `.pythonlibs/` — 101 MB of installed pip packages
- `__pycache__/` — Compiled Python bytecode
- `uv.lock` — Dependency lock file (reproducible from pyproject.toml)

## How to Access Full Git History

The complete development history of the Python codebase is preserved in
the git log. To view it:

```bash
# View all commits that touched Python files
git log --all -- "*.py" app.py dns_analyzer.py

# View a specific file's history
git log --follow -p -- dns_analyzer.py

# Restore any file at a specific commit
git show <commit>:dns_analyzer.py
```

## Go Codebase Location

The active, maintained codebase is at `go-server/`. See `replit.md` for
current architecture documentation.
