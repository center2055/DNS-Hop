## DNS Hop v1.4

This release hardens resolver tamper detection, adds first-class diagnostics logging, and expands the built-in resolver catalog with additional verified providers.

### Highlights
- Broadened DNS tamper detection across multiple reserved-domain probe families instead of relying on a single invalid-domain pattern
- Added stronger poisoning evidence, including sinkhole-style answers, policy-style mismatches, and per-family probe summaries
- Added shared diagnostics logging for startup, resolver loading, benchmark failures, exports, and system DNS switching
- Expanded the built-in resolver catalog with FFMUC, dnsforge, Wikimedia DNS, FortiGuard (managed), and WatchGuard DNSWatch (managed)

### Diagnostics
- Logs are written under `%LOCALAPPDATA%\DNS Hop\Logs`
- The smoke test now reports the active diagnostics log path

### Assets
- `DNS-Hop-Setup-v1.4.exe`: Windows installer
- `DNS-Hop-Portable-v1.4.zip`: portable Windows build
