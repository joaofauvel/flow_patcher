# flow-patcher

> **Please support the developer!** Flow is an excellent focus timer built with
> care. If you find it useful, [**buy it**](https://www.flow.app).
> This project exists for educational purposes and personal use.

Patches [Flow](https://flow.app) to enable Pro features, disable telemetry,
and preserve user data from the App Store installation.

## Requirements

- **Python** ≥ 3.13
- macOS with Xcode Command Line Tools (`xcode-select --install`)
- [uv](https://docs.astral.sh/uv/)
- [just](https://github.com/casey/just) (optional)

### Tested Flow.app Versions

| Flow Version | macOS | Status | Date |
|:---:|:---:|:---:|:---:|
| 4.6.1 | Tahoe 26.x | Working | 2026-02 |

> [!NOTE]
> Flow is distributed exclusively via the Mac App Store. Apple does not
> provide an archive of previous versions, so only the current release
> can be tested at any given time. If Flow updates and the patch breaks,
> run `just probe` (or `flow-patcher probe`) to diagnose the issue.

## Quick start

```bash
just patch                     # patches /Applications/Flow.app by default
open ~/Applications/Flow.app   # launch the patched copy
```

The original App Store installation is **never modified**. The patcher copies
`Flow.app` to `~/Applications/`, applies the patch there, and migrates your
data from the sandboxed container.

## Usage

### Patch

```bash
# Default (assumes /Applications/Flow.app):
just patch

# Or specify source explicitly:
just patch APP=/path/to/Flow.app

# Without just:
uv run flow-patcher patch /Applications/Flow.app
```

This will:
1. Copy `Flow.app` to `~/Applications/`
2. Compile and inject `FlowPatch.dylib`
3. Ad-hoc re-sign the app
4. Migrate CoreData, preferences, and settings from the sandboxed container

### Restore

```bash
just restore          # removes ~/Applications/Flow.app
uv run flow-patcher restore Flow.app
```

This deletes the patched copy from `~/Applications/`. The original in
`/Applications/` is untouched.

## What the patch does

`FlowPatch.dylib` is loaded at launch via an injected `LC_LOAD_DYLIB` command.
It hooks several runtime entry points:

| Hook | Effect |
|------|--------|
| `NSUserDefaults.boolForKey:` | Returns `YES` for `isProSubscriptionActive` |
| `NSUserDefaults.objectForKey:` | Intercepts reads of RevenueCat's `purchaserInfo` cache and injects a fake pro entitlement before the SDK parses it |
| `NSUserDefaults.set*ForKey:` | Forces `YES` on writes to the pro key; injects entitlement into `purchaserInfo` writes; blocks deletion of the pro key |
| `RCEntitlementInfo.isActive` | Returns `YES` |
| `NSPersistentContainer.loadPersistentStores` | Injects `NSPersistentHistoryTrackingKey` to prevent CoreData read-only mode |
| Firebase (`FIRAnalytics`, `GDTCORTransport`, …) | No-ops event logging, heartbeats, and data transport (deferred to post-launch so Firestore can initialize) |
| `NSApplicationWillTerminateNotification` | Forces clean exit after 100ms to bypass gRPC 10-second shutdown hang |

## Project layout

```
flow_patcher/
  __init__.py
  cli.py           Command-line interface (patch / restore / probe)
  inject.py        Mach-O LC_LOAD_DYLIB injector
  patch_dylib.m    ObjC dylib source (the actual hooks)
  probe.py         Flow.app compatibility checker
frida/
  script.js        Frida hook used during initial reverse engineering
  diag.js          Diagnostic disassembler for identifying call sites
  example.py       Frida loader script
tests/
  conftest.py      Pytest fixtures
  test_cli.py      CLI command and helper tests
  test_cli_probe.py CLI probe command tests
  test_dylib.m     Standalone dylib tests
  test_dylib_hooks.py Tests for dylib hooks
  test_inject.py   Mach-O injector tests (synthetic binaries)
  test_integration.py Integration tests with live Flow.app
  test_probe.py    Probe logic tests
compatibility.json Known-good configurations for probe
EXECUTION_FLOW.md  Detailed binary execution flow documentation
justfile           Task runner shortcuts
pyproject.toml     uv/pip project metadata
README.md          This file
```

## Version Probe

Check compatibility with your installed version of Flow *before* patching:

```bash
# Human-readable check
just probe              # or: uv run flow-patcher probe /Applications/Flow.app

# JSON output
just probe --json

# Save current compatibility baseline
just probe --save
```

This verifies:
- Mach-O header padding available for injection
- Existence of required ObjC classes (RevenueCat, Firebase, etc.)
- Expected selectors for swizzling

## Testing

```bash
# Run checks (lint, format, mypy, tests)
just check

# Fix lint and format issues
just fix

# Run unit tests (fast, no Flow.app required)
just test

# Run integration tests (requires /Applications/Flow.app)
just test-integration
```

## Notes

- The patched app runs **unsandboxed** — it reads preferences and CoreData from
  `~/Library/` instead of `~/Library/Containers/`. Data is migrated
  automatically on first patch.
- Re-running `just patch` re-copies from the original and re-applies everything.
  Your settings in `~/Library/Preferences/` are preserved.
- If Flow updates in the App Store, just run `just patch` again.

## Risks & Limitations

- **Fragility**: The patch injects a fake entitlement into RevenueCat's cached JSON blob. If RevenueCat changes their schema (e.g., renaming the "subscriber" key), the patch may silently fail to unlock Pro features.
- **Updates**: This patch is version-specific. While it works for minor updates, major Flow updates might change class names or obfuscation, requiring updates to `flow-patcher`. Always run `just probe` before patching a new version.

