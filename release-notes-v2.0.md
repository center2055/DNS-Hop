## DNS Hop v2.0

A full UI redesign on FluentAvalonia in the Windows 11 25H2 settings style, plus DNS profiles, multi-language support, geo-aware recommendations, a DNS leak test, and a refreshed Logs page.

### Highlights
- New shell built on FluentAvalonia `NavigationView` with a left rail (Home, Benchmark, Resolvers, Results, Profiles, Network, Logs, Settings, About) and Mica backdrop on Windows 11
- Windows title bar follows the in-app theme; Light / Dark / System theme switch with no restart
- Win 11 Home page with active-resolver card and quick-action rows: Run benchmark, Apply best, Check DNS tampering, Restore previous DNS
- **DNS Profiles** — save preferred + alternate IPv4 / IPv6 pairs and apply them with one click. Built-in profiles for Cloudflare Privacy, Quad9 Secure, AdGuard Family, Mullvad and Google Public DNS
- **Geo-aware recommendations** — best resolvers for your region detected from Cloudflare CDN trace (country-only, no precise geolocation)
- Curated resolver metadata (operator, country, no-log policy, ad/malware/adult filtering) surfaced as badges in the resolver list and results
- **DNS leak test** — verifies that resolution actually goes through the resolver you applied, using `whoami.cloudflare`
- **Apply history** — the last five applied DNS configurations are remembered with a one-click "Restore previous"
- Results page with two recommendation cards (Primary / Secondary), per-row latency bars, status dots and inline Apply
- Network page with one card per adapter, aligned label grid, integrated leak-test
- Logs page with INFO / WARN / ERROR severity colouring, level filters, search and export
- Settings page rebuilt with `SettingsExpander` controls (the native Win 11 pattern)

### Localization
- **5 languages out of the box**: English, German, French, Russian, Simplified Chinese
- Auto-detects from the OS UI language on first launch, with a manual override in Settings → Display language
- Switching languages is reactive — no restart needed

### Performance
- Project-wide compiled bindings
- Async settings persistence on shutdown (fixes the ~1.5 s lag when closing the window)
- Virtualised resolver list replaces the previous custom-themed DataGrid
- Live elapsed-time ticker and ETA on the Benchmark page so long runs no longer feel stuck

### Assets
- `DNS-Hop-Setup-v2.0.exe`: Windows installer
- `DNS-Hop-Portable-v2.0.zip`: portable Windows build
- `DNS-Hop-AppImage-v2.0-x86_64.AppImage`: Linux AppImage
