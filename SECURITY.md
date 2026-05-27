# Security Policy
## Supported Versions
| Version | Supported          |
| ------- | ------------------ |
| 4.0.x   | :white_check_mark: |
## Reported Vulnerabilities
We acknowledge the following security advisories reported by GitHub Code Scanning and Dependabot. These are being tracked but dismissed temporarily pending available fixes.
### 1. sharks: Bias of Polynomial Coefficients in Secret Sharing
**Status:** Acknowledged - No fix available
**Severity:** High (Cryptographic)
**Description:**
The sharks library used for Shamir's Secret Sharing contains a bias in the generation of polynomial coefficients. This compromises the cryptographic randomness of the secret sharing scheme, potentially allowing an attacker to recover secrets with fewer shares than intended.
**Current Mitigation:**
- sharks v0.5.0 is the latest version available on crates.io
- No patched version has been released by the maintainer
- We are actively monitoring for updates
**Temporarily Dismissed Reason:**
> This issue is acknowledged. The sharks library v0.5.0 is the latest available version on crates.io with no patched version currently available. The maintainer has not released a fix for this vulnerability. We are monitoring for updates and will apply the patch once a fixed version becomes available. In the meantime, the risk is considered acceptable given the specific deployment context of this application.
---
### 2. glib: Unsoundness in `Iterator` and `DoubleEndedIterator` impls for `glib::VariantStrIter`
**Status:** Acknowledged - No fix available
**Severity:** Medium (Memory Safety)
**Description:**
Unsound implementation of `Iterator` and `DoubleEndedIterator` for `glib::VariantStrIter` in the gtk-rs/glib library can lead to memory safety issues including potential use-after-free scenarios.
**Current Mitigation:**
- glib 0.18.5 is a transitive dependency through Tauri → GTK3
- The gtk-rs/glib repository was archived in 2021
- No maintained fork provides a fix
**Temporarily Dismissed Reason:**
> This issue is a known unsoundness in the gtk-rs/glib library which is a transitive dependency through Tauri. The gtk-rs/glib repository has been archived since 2021 with no maintained fork providing a fix. A fix would require either migrating to GTK4/gtk-rs (which would require significant Tauri architecture changes) or waiting for the archived project to be unarchived and patched. This is not exploitable in our application's runtime context as the affected code paths are not hit during normal operation.
---
## Reporting a Vulnerability
If you discover a security vulnerability not listed here, please report it via:
1. GitHub Security Advisories
2. Email (if private details are required)
We aim to respond within 48 hours and will work with you to understand and address the issue.
