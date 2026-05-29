export type Accent = 'sky' | 'mint' | 'sun';
export type StageModeId = 'benchmark' | 'profiles' | 'desktop';

export type GitHubRepo = {
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
  subscribers_count?: number;
  pushed_at: string;
  html_url: string;
  homepage: string;
  description: string;
};

export type GitHubAsset = {
  name: string;
  size: number;
  download_count: number;
  browser_download_url: string;
};

export type GitHubRelease = {
  tag_name: string;
  name: string;
  html_url: string;
  published_at: string;
  body: string;
  assets: GitHubAsset[];
};

export const navItems = [
  { label: 'What is new', href: '#why' },
  { label: 'Workflow', href: '#workflow' },
  { label: 'Live release', href: '#release' },
  { label: 'FAQ', href: '#faq' },
];

export const heroSignals = [
  {
    kicker: 'Redesigned',
    title: 'Windows 11 25H2 Settings shell, in your DNS tool',
    body: 'FluentAvalonia NavigationView, Mica backdrop, theme-aware title bar.',
    accent: 'sky' as const,
  },
  {
    kicker: 'Profiles',
    title: 'Preferred + alternate DNS, IPv4 + IPv6, one click',
    body: 'Built-in profiles for Cloudflare, Quad9, AdGuard, Mullvad, Google.',
    accent: 'mint' as const,
  },
  {
    kicker: 'Multilingual',
    title: 'Five languages out of the box',
    body: 'English, German, French, Russian and Simplified Chinese with live switching.',
    accent: 'sun' as const,
  },
];

export const stageModes = [
  {
    id: 'benchmark' as const,
    label: 'Benchmark',
    title: 'Cached, uncached and DotCom probes side by side.',
    body: 'DNS Hop keeps the real test signals visible so you can spot fast-but-unstable servers before you switch.',
    points: [
      'Three timing probes per resolver, with stddev on repeated runs',
      'DNSSEC and NXDOMAIN-hijack reliability checks',
      'Live ETA and resolver-count progress so long runs stay readable',
    ],
    badge: 'Latency story',
  },
  {
    id: 'profiles' as const,
    label: 'Profiles',
    title: 'Save preferred + alternate pairs and apply them with one click.',
    body: 'Pick a winner once. Apply the same DNS configuration whenever you want, with IPv4 and IPv6 in the same gesture.',
    points: [
      'Builtins for Cloudflare Privacy, Quad9 Secure, AdGuard Family, Mullvad and Google',
      'Geo-aware ranking biases toward resolvers with a PoP in your region',
      'Apply history with one-click "restore previous DNS"',
    ],
    badge: 'Decision flow',
  },
  {
    id: 'desktop' as const,
    label: 'Desktop',
    title: 'Ship the same workflow to Windows and Linux.',
    body: 'A Windows installer, a Windows portable zip and a Linux AppImage are produced from the same release pipeline so testing stays straightforward across desktop setups.',
    points: [
      'Windows installer plus portable zip',
      'Linux AppImage built and smoke-tested on Debian, Fedora and Arch by CI',
      'Five UI languages, auto-detected from the OS',
      'CSV, JSON and chart-PNG export for results',
    ],
    badge: 'Ship shape',
  },
];

export const featureCards = [
  {
    title: 'DNS leak test',
    body: 'After you apply a resolver, DNS Hop verifies that resolution actually goes through it using a probe to whoami.cloudflare.',
    accent: 'sky' as const,
  },
  {
    title: 'Curated metadata',
    body: 'Operator, country, no-log policy and content-filtering flags are surfaced as badges in the resolver list and recommendation cards.',
    accent: 'mint' as const,
  },
  {
    title: 'Settings as expanders',
    body: 'The Settings page is built from FluentAvalonia SettingsExpander rows, the same control pattern as Windows 11 Settings.',
    accent: 'sun' as const,
  },
  {
    title: 'Logs you can read',
    body: 'INFO / WARN / ERROR severity colouring, a filter, and a one-click export, so diagnostics finally fit on screen.',
    accent: 'sky' as const,
  },
  {
    title: 'Theme-aware chrome',
    body: 'The Windows title bar follows the in-app Light/Dark choice via DWM, and Mica stays on when you let DNS Hop follow the OS.',
    accent: 'mint' as const,
  },
  {
    title: 'No paywall positioning',
    body: 'DNS Hop is framed as an accessible tool, not a crippled teaser for a paid tier.',
    accent: 'sun' as const,
  },
];

export const workflowSteps = [
  {
    index: '01',
    title: 'Benchmark the public list',
    body: 'Watch resolver counts and ETA tick down live.',
  },
  {
    index: '02',
    title: 'Pick a profile or a row',
    body: 'Built-in profiles or any row from your results.',
  },
  {
    index: '03',
    title: 'Apply and verify',
    body: 'One click to switch, then the leak test confirms it.',
  },
];

export const faqItems = [
  {
    question: 'What changed in v2?',
    answer:
      'The whole shell was redesigned around the Windows 11 25H2 Settings look using FluentAvalonia. v2 also adds DNS profiles with built-in vendor presets, geo-aware recommendations, a DNS leak test, an apply-history with restore-previous, a localized UI in five languages, a refreshed logs page, and a softer card system that adapts to Light / Dark / System theme.',
  },
  {
    question: 'Which languages does the UI support?',
    answer:
      'English, German, French, Russian and Simplified Chinese, auto-detected from your OS UI language on first launch. You can override the language in Settings, and switching is reactive, with no restart.',
  },
  {
    question: 'Does it benchmark encrypted DNS?',
    answer:
      'Yes. The resolver list includes classic UDP/TCP, DNS-over-HTTPS and DNS-over-TLS endpoints, and the protocol stays visible in the results.',
  },
  {
    question: 'Can I use it without installing anything?',
    answer:
      'Yes. Releases ship a Windows portable zip and a Linux AppImage alongside the Windows installer, so you can run DNS Hop without a traditional install flow.',
  },
  {
    question: 'How does the leak test work?',
    answer:
      'After you apply a resolver, DNS Hop queries whoami.cloudflare and compares the answer to the resolver you expect. Same IP or same anycast block ✓; different operator ✗.',
  },
];

export const fallbackRepo: GitHubRepo = {
  stargazers_count: 33,
  forks_count: 5,
  open_issues_count: 1,
  subscribers_count: 2,
  pushed_at: '2026-05-27T18:18:33Z',
  html_url: 'https://github.com/center2055/DNS-Hop',
  homepage: 'https://github.com/center2055/DNS-Hop/releases/latest',
  description: 'Cross-platform DNS benchmarking, profiles and one-click switching for Windows and Linux.',
};

export const fallbackRelease: GitHubRelease = {
  tag_name: 'v2.0',
  name: 'DNS Hop v2.0',
  html_url: 'https://github.com/center2055/DNS-Hop/releases/tag/v2.0',
  published_at: '2026-05-27T18:18:33Z',
  body: [
    '## DNS Hop v2.0',
    '',
    '- Full UI redesign on FluentAvalonia in the Windows 11 25H2 Settings style',
    '- DNS Profiles (preferred + alternate, IPv4 + IPv6) with built-in vendor presets',
    '- Geo-aware recommendations + curated resolver metadata',
    '- DNS leak test + apply history with restore-previous',
    '- Refreshed Results, Network and Logs pages',
    '- Five UI languages: English, German, French, Russian, Simplified Chinese',
  ].join('\n'),
  assets: [
    {
      name: 'DNS-Hop-Setup-v2.0.exe',
      size: 34_603_008,
      download_count: 0,
      browser_download_url: 'https://github.com/center2055/DNS-Hop/releases/download/v2.0/DNS-Hop-Setup-v2.0.exe',
    },
    {
      name: 'DNS-Hop-Portable-v2.0.zip',
      size: 44_040_192,
      download_count: 0,
      browser_download_url: 'https://github.com/center2055/DNS-Hop/releases/download/v2.0/DNS-Hop-Portable-v2.0.zip',
    },
    {
      name: 'DNS-Hop-AppImage-v2.0-x86_64.AppImage',
      size: 41_788_608,
      download_count: 0,
      browser_download_url: 'https://github.com/center2055/DNS-Hop/releases/download/v2.0/DNS-Hop-AppImage-v2.0-x86_64.AppImage',
    },
  ],
};
