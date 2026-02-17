# DNS Tool — Go Build Tag Strategy for Two-Repo Open Core

> **Date:** 2026-02-17
> **Status:** Research / Design (no code changes)
> **Scope:** DnsToolWeb (public, BSL 1.1) + dnstool-intel (private, BSL 1.1)
> **References:** BOUNDARY_MATRIX.md, STUB_AUDIT.md, LICENSING.md

---

## 1. Industry Survey: How Open-Core Go Projects Separate OSS from Enterprise

### 1.1 HashiCorp (Vault, Consul) — Build Tags in a Single Repo

HashiCorp uses **Go build tags** with a `_oss.go` / `_ent.go` file-pair convention:

```
vault/
├── seal.go              # Common interface (no tag)
├── seal_oss.go          # //go:build !enterprise  — stub / OSS default
└── seal_ent.go          # //go:build enterprise   — full implementation
```

- **Tag name:** `enterprise`
- **Negation pattern:** OSS files carry `//go:build !enterprise` so they are excluded when the enterprise tag is present.
- **Build commands:** `go build` (OSS) vs. `go build -tags enterprise` (Enterprise).
- **Key insight:** Both files define the same symbols (same function names, same package). Go's build constraint system ensures exactly one file is compiled. There is never a "duplicate symbol" error because the constraints are mutually exclusive.
- **Enterprise code ships in the same repo** but is not compiled into OSS binaries. HashiCorp's public repo contains both `_oss.go` and `_ent.go` files — the enterprise source is visible but only activates with the tag.
- **License:** BSL 1.1 (same as DNS Tool).

### 1.2 CockroachDB — Directory Separation + Build Tags

CockroachDB uses a **`pkg/ccl/` directory** to isolate enterprise (CCL-licensed) code:

```
cockroachdb/cockroach/
├── pkg/
│   ├── sql/               # Core (Apache 2.0 / CockroachDB Software License)
│   ├── kv/                # Core
│   └── ccl/               # Enterprise — Cockroach Community License
│       ├── backupccl/
│       ├── changefeedccl/
│       └── partitionccl/
```

- **Build commands:** `make build` (includes CCL) vs. `make buildoss` (excludes CCL).
- **Key insight:** The `ccl/` directory is a separate Go package tree. Enterprise features register themselves into the core via `init()` functions and hook registries, not by replacing files.
- **Relevant to DNS Tool:** This pattern works when enterprise code is additive (new packages, new features). It is less suitable when intelligence needs to replace stub implementations in the same package.

### 1.3 GitLab — Directory Separation (Non-Go)

GitLab uses an `ee/` directory in a single Ruby/Rails repo:

- CE builds exclude `ee/`. EE builds include it.
- Previously maintained separate CE and EE repos; merged into one in GitLab 12.3 (2019) to reduce ~150 merge conflicts per security release.
- **Key insight for DNS Tool:** Maintaining two separate repos increases drift risk significantly. GitLab's experience shows that a single-repo approach with directory separation is operationally simpler. However, DNS Tool's licensing model (keeping intelligence source out of the public repo entirely) requires two repos.

### 1.4 Summary: Which Pattern Fits DNS Tool?

| Approach | Single Repo? | Intelligence Source Visible? | Fits DNS Tool? |
|----------|:---:|:---:|:---:|
| HashiCorp (build tags, `_oss`/`_ent` pairs) | Yes | Yes (source in public repo) | **Partially** — tag mechanism is right, but we need two repos |
| CockroachDB (directory + `init()` hooks) | Yes | Yes (in `ccl/` dir) | **No** — we need to replace stubs, not just add packages |
| GitLab (directory separation) | Yes | Yes (in `ee/` dir) | **No** — intelligence must not be in public repo |
| **DNS Tool (proposed)** | **No (two repos)** | **No** | **HashiCorp tag pattern + overlay build step** |

**Conclusion:** Use the HashiCorp `//go:build` tag mechanism, but adapted for a two-repo architecture where the private repo's tagged files overlay the public repo's stubs at build time.

---

## 2. Recommended Build Tag Strategy

### 2.1 Tag Name: `intel`

| Candidate | Pros | Cons | Decision |
|-----------|------|------|----------|
| `enterprise` | Industry standard (HashiCorp, CRDB) | Implies a license tier, not a code source. DNS Tool is BSL everywhere. | No |
| `proprietary` | Accurate | Negative connotation; long; uncommon in Go ecosystem | No |
| `ent` | Short, common | Same "license tier" confusion as `enterprise` | No |
| **`intel`** | **Matches project vocabulary ("intelligence"), short, unique, clear** | Less common in industry | **Yes** |

**Usage:**
```go
//go:build !intel     ← public stub file (compiled when building from public repo alone)
//go:build intel      ← private intelligence file (compiled when building with dnstool-intel)
```

**Build commands:**
```bash
# Public build (OSS-equivalent, stubs return safe defaults)
go build -o dns-tool-server ./cmd/server

# Internal build (full intelligence)
go build -tags intel -o dns-tool-server ./cmd/server
```

### 2.2 File Naming Convention

**Pattern:** `<name>_oss.go` (public stub) / `<name>_intel.go` (private intelligence)

Current file names like `infrastructure.go` contain both framework code (types, utilities) and intelligence (provider maps, detection logic). These must be split into three files:

| File | Build Tag | Contents | Repo |
|------|-----------|----------|------|
| `infrastructure.go` | None (always compiled) | Types, interfaces, constants, utility functions — the API contract | Public (DnsToolWeb) |
| `infrastructure_oss.go` | `//go:build !intel` | Stub implementations returning safe defaults; empty maps | Public (DnsToolWeb) |
| `infrastructure_intel.go` | `//go:build intel` | Full provider databases, detection algorithms, scoring logic | Private (dnstool-intel) |

**Naming rules:**
1. The base file (`infrastructure.go`) has no build tag and defines the shared contract (types, interfaces, exported function signatures via delegation).
2. The `_oss.go` file carries `//go:build !intel` and contains stub implementations.
3. The `_intel.go` file carries `//go:build intel` and contains the real implementations.
4. Both `_oss.go` and `_intel.go` define the same symbols. Go's build constraints ensure only one is compiled.

### 2.3 How the Private Repo Overlays the Public Repo

**Mechanism: Go workspace or replace directive + symlink/copy at build time.**

Since Go requires all files in the same package to be in the same directory, the private repo's `_intel.go` files must be present alongside the public repo's files at build time. Three approaches:

#### Option A: Symlink Overlay (Recommended)

```bash
# Build script (internal CI only)
git clone git@github.com:careyjames/DnsToolWeb.git  workdir
git clone git@github.com:careyjames/dnstool-intel.git  intel

# Symlink intel files into the public repo's package directories
ln -sf $(pwd)/intel/analyzer/infrastructure_intel.go \
       workdir/go-server/internal/analyzer/infrastructure_intel.go
ln -sf $(pwd)/intel/analyzer/providers_intel.go \
       workdir/go-server/internal/analyzer/providers_intel.go
# ... repeat for each _intel.go file

cd workdir
go build -tags intel -o dns-tool-server ./go-server/cmd/server
```

**Why symlinks:**
- The public repo never contains intel files (not even in `.gitignore`).
- Go treats symlinked `.go` files as regular package members.
- The build script is the single source of truth for the overlay.
- No changes to `go.mod` or module paths required.

#### Option B: Copy Overlay (CI-Friendly Fallback)

Same as Option A but using `cp` instead of `ln -sf`. Suitable for CI environments where symlinks may not work (some container filesystems).

#### Option C: Go Workspace (go.work)

Not suitable here. Go workspaces (`go.work`) operate at the module level, not the file level. Since both repos need to contribute files to the same Go package (`internal/analyzer`), workspaces cannot solve this problem.

### 2.4 Build Pipeline

#### Public Build (GitHub Actions on DnsToolWeb)

```yaml
# .github/workflows/build-public.yml
- name: Build (public, stubs only)
  run: |
    cd go-server
    go build -o dns-tool-server ./cmd/server
    # No -tags intel → _oss.go files compiled, _intel.go files excluded
```

#### Internal Build (Private CI, e.g., GitHub Actions on dnstool-intel)

```yaml
# .github/workflows/build-internal.yml
- name: Checkout public repo
  uses: actions/checkout@v4
  with:
    repository: careyjames/DnsToolWeb
    path: workdir

- name: Checkout private repo
  uses: actions/checkout@v4
  with:
    path: intel

- name: Overlay intel files
  run: |
    # Script that symlinks or copies all _intel.go files
    # into the correct package directories in workdir/
    ./intel/scripts/overlay.sh workdir

- name: Build (full intelligence)
  run: |
    cd workdir
    go build -tags intel -o dns-tool-server ./go-server/cmd/server
```

#### overlay.sh (lives in private repo)

```bash
#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?Usage: overlay.sh <public-repo-dir>}"

INTEL_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Each line: <intel-source-path> <target-path-relative-to-public-repo>
while IFS=' ' read -r src dst; do
    cp "$INTEL_DIR/$src" "$TARGET/$dst"
done <<'MANIFEST'
analyzer/infrastructure_intel.go   go-server/internal/analyzer/infrastructure_intel.go
analyzer/providers_intel.go        go-server/internal/analyzer/providers_intel.go
analyzer/ip_investigation_intel.go go-server/internal/analyzer/ip_investigation_intel.go
analyzer/dkim_state_intel.go       go-server/internal/analyzer/dkim_state_intel.go
analyzer/confidence_intel.go       go-server/internal/analyzer/confidence_intel.go
analyzer/manifest_intel.go         go-server/internal/analyzer/manifest_intel.go
analyzer/ai_surface/http_intel.go           go-server/internal/analyzer/ai_surface/http_intel.go
analyzer/ai_surface/llms_txt_intel.go       go-server/internal/analyzer/ai_surface/llms_txt_intel.go
analyzer/ai_surface/robots_txt_intel.go     go-server/internal/analyzer/ai_surface/robots_txt_intel.go
analyzer/ai_surface/poisoning_intel.go      go-server/internal/analyzer/ai_surface/poisoning_intel.go
MANIFEST

echo "Overlay complete: $(wc -l <<< "$(find "$TARGET" -name '*_intel.go')")" files
```

### 2.5 Handling the Same-Package Requirement

**Problem:** Go requires all files declaring `package analyzer` to be in the same directory. The private repo cannot be a separate module or package.

**Solution:** The overlay approach (Section 2.3) solves this directly. After symlink/copy, all files — base, `_oss.go`, and `_intel.go` — coexist in the same directory. Go sees them as one package. The build tag ensures only one of `_oss.go` / `_intel.go` is compiled for each feature.

**Critical rule:** Every symbol defined in `_oss.go` must be defined with the exact same signature in `_intel.go`. They are compile-time alternatives, not supplements.

---

## 3. File Structure: Concrete Example with `infrastructure.go`

### 3.1 Current State (Single File, Mixed Concerns)

```
go-server/internal/analyzer/infrastructure.go    (581 lines)
├── Types: providerInfo, infraMatch, dsDetection (FRAMEWORK)
├── Constants: feat*, name*, tier* (FRAMEWORK)
├── Provider maps: enterpriseProviders (22 entries), mxProviderPatterns (28 entries),
│   nsProviderPatterns (24 entries), webHostingPatterns (22 entries),
│   ptrHostingPatterns (14 entries), legacyProviderBlocklist (10 entries) (DUAL/INTELLIGENCE)
├── Empty stub maps: selfHostedEnterprise, governmentDomains, managedProviders,
│   hostingProviders, etc. (INTELLIGENCE stubs)
├── Working functions: matchEnterpriseProvider, identifyEmailProvider,
│   identifyDNSProvider, identifyWebHosting (DUAL)
├── Stub functions: matchSelfHostedProvider, matchGovernmentDomain,
│   detectDMARCReportProviders, etc. (INTELLIGENCE stubs)
└── Utility functions: parentZone, applyHostingDefaults, containsStr (FRAMEWORK)
```

### 3.2 Proposed Three-File Split

#### `infrastructure.go` — Framework (always compiled, no build tag)

```
// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

// --- Types ---
type providerInfo struct { ... }
type infraMatch struct { ... }
type dsDetection struct { ... }

// --- Constants (feature labels, tier labels) ---
const (
    featDDoSProtection       = "DDoS protection"
    featAnycast              = "Anycast"
    // ... all feat* and tier* constants
    tierEnterprise = "enterprise"
    tierManaged    = "managed"
)

// --- Utility functions (pure logic, no intelligence) ---
func parentZone(domain string) string { ... }
func applyHostingDefaults(hosting, dnsHosting, emailHosting string, isNoMail bool) (string, string, string) { ... }
func containsStr(ss []string, s string) bool { ... }
func zoneCapability(zoneKey string) string { return zoneKey + " management" }
```

#### `infrastructure_oss.go` — Stubs (public repo, `//go:build !intel`)

```
//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See github.com/careyjames/dnstool-intel for the full version.
package analyzer

import (
    "context"
    "net"
    "strings"
)

// --- Provider name constants (commodity knowledge, safe to expose) ---
const (
    nameAmazonRoute53   = "Amazon Route 53"
    nameGoogleWorkspace = "Google Workspace"
    nameMicrosoft365    = "Microsoft 365"
    nameCloudflare      = "Cloudflare"
    // ... other well-known names
)

// --- Stub maps (empty) ---
var enterpriseProviders  = map[string]providerInfo{}
var legacyProviderBlocklist = map[string]bool{}
var selfHostedEnterprise = map[string]providerInfo{}
var governmentDomains    = map[string]providerInfo{}
var managedProviders     = map[string]providerInfo{}
var hostingProviders     = map[string]string{}
// ... all other empty maps

// --- MX/NS/Web provider patterns (basic detection, commodity) ---
var mxProviderPatterns  = map[string]string{ /* small set or empty */ }
var nsProviderPatterns  = map[string]string{ /* small set or empty */ }
var webHostingPatterns  = map[string]string{ /* small set or empty */ }
var ptrHostingPatterns  = map[string]string{}

// --- Stub function implementations ---
func (a *Analyzer) AnalyzeDNSInfrastructure(domain string, results map[string]any) map[string]any {
    return map[string]any{
        "provider_tier":      "standard",
        "provider_features":  []string{},
        "is_government":      false,
        "alt_security_items": []string{},
        "assessment":         "Standard DNS",
    }
}

func (a *Analyzer) GetHostingInfo(ctx context.Context, domain string, results map[string]any) map[string]any {
    return map[string]any{ /* safe defaults */ }
}

func (a *Analyzer) DetectEmailSecurityManagement(spf, dmarc, tlsrpt, mtasts map[string]any, domain string, dkim map[string]any) map[string]any {
    return map[string]any{ /* safe defaults */ }
}

func matchEnterpriseProvider(nsList []string) *infraMatch { return nil }
func matchSelfHostedProvider(nsStr string) *infraMatch    { return nil }
// ... all other stub functions with safe defaults
```

#### `infrastructure_intel.go` — Full Intelligence (private repo, `//go:build intel`)

```
//go:build intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full intelligence implementation.
package analyzer

import (
    "context"
    "net"
    "strings"
)

// --- Provider name constants ---
const (
    nameAmazonRoute53   = "Amazon Route 53"
    nameGoogleWorkspace = "Google Workspace"
    nameMicrosoft365    = "Microsoft 365"
    nameCloudflare      = "Cloudflare"
    // ... complete list including proprietary additions
)

// --- Full provider databases ---
var enterpriseProviders = map[string]providerInfo{
    "awsdns":     { Name: nameAmazonRoute53, Tier: tierEnterprise, Features: []string{...} },
    "cloudflare": { Name: nameCloudflare, Tier: tierEnterprise, Features: []string{...} },
    // ... 22+ entries
}

var selfHostedEnterprise = map[string]providerInfo{
    // Private intelligence: self-hosted detection patterns
}

var governmentDomains = map[string]providerInfo{
    // Private intelligence: government domain classification
}

// ... all other fully-populated maps

// --- Full function implementations ---
func (a *Analyzer) AnalyzeDNSInfrastructure(domain string, results map[string]any) map[string]any {
    // Full tier detection: enterprise → self-hosted → managed → government → standard
    // Uses all provider maps, alternative security item collection, etc.
}

func matchEnterpriseProvider(nsList []string) *infraMatch {
    // Full implementation with blocklist check + pattern matching
}

// ... all other functions with complete intelligence
```

### 3.3 Complete Directory Layout (Both Repos)

#### Public Repo: `careyjames/DnsToolWeb`

```
DnsToolWeb/
├── go-server/
│   ├── cmd/server/main.go
│   ├── internal/
│   │   ├── analyzer/
│   │   │   ├── analyzer.go                    # Core orchestrator (no tag)
│   │   │   ├── infrastructure.go              # Types, constants, utilities (no tag)
│   │   │   ├── infrastructure_oss.go          # //go:build !intel — stubs
│   │   │   ├── providers.go                   # Types, capability constants (no tag)
│   │   │   ├── providers_oss.go               # //go:build !intel — stubs
│   │   │   ├── ip_investigation.go            # Types, IP validation (no tag)
│   │   │   ├── ip_investigation_oss.go        # //go:build !intel — stubs
│   │   │   ├── confidence.go                  # Full (no tag, pure framework)
│   │   │   ├── dkim_state.go                  # State machine (no tag)
│   │   │   ├── dkim_state_oss.go              # //go:build !intel — stub classifyDKIMState
│   │   │   ├── manifest.go                    # Types, filter (no tag)
│   │   │   ├── manifest_oss.go                # //go:build !intel — empty manifest
│   │   │   ├── edge_cdn.go                    # Types (no tag)
│   │   │   ├── edge_cdn_oss.go                # //go:build !intel — stubs
│   │   │   ├── saas_txt.go                    # Types (no tag)
│   │   │   ├── saas_txt_oss.go                # //go:build !intel — stubs
│   │   │   ├── commands.go                    # Full (no tag, pure framework)
│   │   │   ├── posture.go                     # Types (no tag)
│   │   │   ├── posture_oss.go                 # //go:build !intel — stubs
│   │   │   ├── remediation.go                 # Types (no tag)
│   │   │   ├── remediation_oss.go             # //go:build !intel — stubs
│   │   │   ├── ai_surface/
│   │   │   │   ├── scanner.go                 # Scanner type, exported API (no tag)
│   │   │   │   ├── http_oss.go                # //go:build !intel
│   │   │   │   ├── llms_txt_oss.go            # //go:build !intel
│   │   │   │   ├── robots_txt_oss.go          # //go:build !intel
│   │   │   │   └── poisoning_oss.go           # //go:build !intel
│   │   │   └── ... (other non-stub files)
│   │   ├── config/
│   │   ├── handlers/
│   │   └── ...
│   └── go.mod
├── build.sh                                   # Public build (no -tags intel)
└── ...
```

#### Private Repo: `careyjames/dnstool-intel`

```
dnstool-intel/
├── analyzer/
│   ├── infrastructure_intel.go                # //go:build intel
│   ├── providers_intel.go                     # //go:build intel
│   ├── ip_investigation_intel.go              # //go:build intel
│   ├── dkim_state_intel.go                    # //go:build intel
│   ├── manifest_intel.go                      # //go:build intel
│   ├── edge_cdn_intel.go                      # //go:build intel
│   ├── saas_txt_intel.go                      # //go:build intel
│   ├── posture_intel.go                       # //go:build intel
│   ├── remediation_intel.go                   # //go:build intel
│   └── ai_surface/
│       ├── http_intel.go                      # //go:build intel
│       ├── llms_txt_intel.go                  # //go:build intel
│       ├── robots_txt_intel.go                # //go:build intel
│       └── poisoning_intel.go                 # //go:build intel
├── scripts/
│   ├── overlay.sh                             # Copies _intel.go files into public repo
│   └── verify_signatures.sh                   # Drift detection (see Section 4)
├── .github/
│   └── workflows/
│       └── build-internal.yml                 # CI: overlay + build -tags intel
└── README.md
```

### 3.4 Files That Do NOT Need Splitting

Based on the BOUNDARY_MATRIX.md analysis:

| File | Reason | Action |
|------|--------|--------|
| `confidence.go` | Pure framework (12 symbols, 0 intelligence) | Keep as-is, no tag needed |
| `commands.go` | Pure framework (28 symbols, 0 intelligence) | Keep as-is, no tag needed |
| `analyzer.go` | Core orchestrator | Keep as-is |
| All handler files | Web layer, no intelligence | Keep as-is |

---

## 4. Guarding Against Drift

The single biggest risk in a two-repo architecture is **signature drift**: a function signature changes in the public repo's `_oss.go` file but the private repo's `_intel.go` file still has the old signature, causing a build failure (or worse, a silent behavioral difference).

### 4.1 Contract Test: Signature Extraction Script

Create a script that extracts all function and variable signatures from `_oss.go` files and produces a machine-comparable manifest:

```bash
#!/usr/bin/env bash
# scripts/extract_stub_signatures.sh
# Extracts function/variable signatures from all _oss.go files
set -euo pipefail

find go-server/internal/analyzer -name '*_oss.go' -print0 | \
  xargs -0 grep -hE '^(func |var |const )' | \
  sort > /tmp/oss_signatures.txt

echo "Extracted $(wc -l < /tmp/oss_signatures.txt) signatures"
cat /tmp/oss_signatures.txt
```

The private repo runs the same extraction on its `_intel.go` files. The CI job compares the two:

```bash
diff <(sort /tmp/oss_signatures.txt) <(sort /tmp/intel_signatures.txt)
```

Any mismatch fails the build.

### 4.2 Go Compiler as the Primary Guard

The strongest drift detector is **the Go compiler itself**. If the internal CI always runs:

```bash
go build -tags intel ./go-server/cmd/server
```

...then any signature mismatch between `_oss.go` and `_intel.go` will produce a compile error like:

```
./infrastructure_intel.go:42:6: matchEnterpriseProvider redeclared in this block
        ./infrastructure_oss.go:97:6: other declaration
```

or more commonly, a "too few arguments" / "too many arguments" error when callers in the base file reference a function whose signature changed.

**This is the most reliable guard and requires zero extra tooling.**

### 4.3 CI Matrix: Build Both Editions

```yaml
# .github/workflows/ci.yml (on public repo)
strategy:
  matrix:
    edition: [oss, intel]
steps:
  - name: Checkout
    uses: actions/checkout@v4

  - name: Checkout intel (intel edition only)
    if: matrix.edition == 'intel'
    uses: actions/checkout@v4
    with:
      repository: careyjames/dnstool-intel
      ssh-key: ${{ secrets.INTEL_DEPLOY_KEY }}
      path: intel

  - name: Overlay (intel edition only)
    if: matrix.edition == 'intel'
    run: ./intel/scripts/overlay.sh .

  - name: Build
    run: |
      TAGS=""
      if [ "${{ matrix.edition }}" = "intel" ]; then
        TAGS="-tags intel"
      fi
      go build $TAGS -o dns-tool-server ./go-server/cmd/server

  - name: Test
    run: |
      TAGS=""
      if [ "${{ matrix.edition }}" = "intel" ]; then
        TAGS="-tags intel"
      fi
      go test $TAGS ./go-server/internal/analyzer/...
```

### 4.4 Automated Stub Interface Contract

Add a `go generate` step or a lightweight Go test that uses `go/ast` to parse both `_oss.go` and `_intel.go` files and compare:

1. Every `func` declaration in `_oss.go` has a matching declaration in `_intel.go` with identical name, receiver, parameters, and return types.
2. Every `var` declaration in `_oss.go` has a matching `var` in `_intel.go` with the same type.
3. Every `const` block matches.

This can be implemented as a test file in the private repo:

```go
//go:build intel

package analyzer_test

func TestStubIntelParity(t *testing.T) {
    // Uses go/ast to parse _oss.go and _intel.go files
    // Compares function signatures
    // Fails if any mismatch detected
}
```

### 4.5 Git Hook: Pre-Push Signature Check

In the public repo, a pre-push hook can:

1. Extract signatures from `_oss.go` files.
2. Write them to `stubs/signatures.json`.
3. Commit alongside any stub changes.

The private repo's CI reads `signatures.json` from the public repo (via git submodule or API) and validates its `_intel.go` files match.

### 4.6 Golden Rule Test Enhancement

The existing `golden_rules_test.go` in the public repo already validates that stub functions return safe defaults. This can be extended:

```go
func TestStubSignaturesDocumented(t *testing.T) {
    // Parse all _oss.go files
    // Verify every exported function is listed in a known manifest
    // Fail if a new function is added without updating the manifest
}
```

---

## 5. Migration Path

### Phase 1: Split Existing Files (Public Repo)

For each stub file, split into three files:
1. `<name>.go` — types, constants, utilities (no build tag)
2. `<name>_oss.go` — `//go:build !intel` — current stub implementations
3. Remove the old combined file

**Order of migration** (by risk, lowest first):
1. `confidence.go` — Pure framework, no split needed (just verify)
2. `commands.go` — Pure framework, no split needed
3. `manifest.go` → `manifest.go` + `manifest_oss.go`
4. `dkim_state.go` → `dkim_state.go` + `dkim_state_oss.go`
5. `providers.go` → `providers.go` + `providers_oss.go`
6. `ai_surface/*.go` → `*_oss.go` variants
7. `infrastructure.go` → `infrastructure.go` + `infrastructure_oss.go` (largest, most complex)
8. `ip_investigation.go` → `ip_investigation.go` + `ip_investigation_oss.go`
9. `edge_cdn.go` → `edge_cdn.go` + `edge_cdn_oss.go` (currently fully exposed — needs stubbing)
10. `saas_txt.go` → `saas_txt.go` + `saas_txt_oss.go` (currently fully exposed — needs stubbing)

### Phase 2: Create Private Repo Files

For each `_oss.go` file, create a corresponding `_intel.go` in the private repo with the full implementation.

### Phase 3: Set Up CI

1. Public repo CI: `go build` (no tags) — must always pass.
2. Private repo CI: overlay + `go build -tags intel` — must always pass.
3. Signature parity check in private repo CI.

### Phase 4: Retire `stubs/` Directory

The current `stubs/go-server/internal/analyzer/` directory becomes unnecessary once the `_oss.go` / `_intel.go` pattern is in place. The stubs are now first-class Go files with build constraints, not a shadow directory.

---

## 6. Key Decisions and Rationale

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Tag name | `intel` | Matches project vocabulary; short; unambiguous; avoids "enterprise" tier confusion |
| File suffix | `_oss.go` / `_intel.go` | Follows HashiCorp convention (`_oss`/`_ent`); immediately clear which is which |
| Overlay mechanism | Copy/symlink in build script | Simplest approach; no Go module changes; private files never in public repo |
| Drift detection | Go compiler + CI matrix | Zero-tooling approach; the compiler is the best signature validator |
| Base file convention | No build tag, contains only types/constants/utilities | Clean separation; base file is the API contract |
| `confidence.go`, `commands.go` | No split needed | Pure framework; BOUNDARY_MATRIX confirms 0 intelligence symbols |
| `edge_cdn.go`, `saas_txt.go` | Need stubbing first | Currently expose full intelligence in public repo (flagged in BOUNDARY_MATRIX) |

---

## 7. Open Questions for Implementation

1. **Should `enterpriseProviders` (22 entries) remain in the public `_oss.go`?** These are commodity knowledge (awsdns→Route 53 is well-known), but the complete set reveals tracking scope. The BOUNDARY_MATRIX classifies this as DUAL. Decision needed: keep a small "Top 5" set in `_oss.go`, or move all entries to `_intel.go`?

2. **Should `mxProviderPatterns` / `nsProviderPatterns` / `webHostingPatterns` remain public?** Same DUAL classification. These are commodity knowledge individually but the complete set is competitive intelligence.

3. **How to handle `init()` in `_intel.go` files?** CockroachDB uses `init()` to register enterprise features. For DNS Tool, the simpler approach is to define the same symbols (not use `init()` to append). This avoids ordering issues.

4. **Should the private repo use a Go module?** The private repo's files are copied into the public repo's module at build time, so they share the public repo's `go.mod`. The private repo does not need its own `go.mod` — it is a collection of `.go` files, not a standalone module.

5. **`dnstool-intel-staging/` directory:** The current staging directory in the public repo should be removed or moved to the private repo once the build-tag system is in place.
