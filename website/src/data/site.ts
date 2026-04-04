export type Accent = 'sky' | 'mint' | 'sun';
export type StageModeId = 'benchmark' | 'switch' | 'portable';

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
  { label: 'Why it hits', href: '#why' },
  { label: 'Workflow', href: '#workflow' },
  { label: 'Live release', href: '#release' },
  { label: 'FAQ', href: '#faq' },
];

export const heroSignals = [
  {
    kicker: 'Benchmark',
    title: 'Three-probe signal, not one fake average',
    body: 'See cached, uncached, and dotcom at once.',
    accent: 'sky' as const,
  },
  {
    kicker: 'Switch',
    title: 'One-click DNS changes without old-tool friction',
    body: 'Pick a winner straight from the table.',
    accent: 'mint' as const,
  },
  {
    kicker: 'Ship',
    title: 'Installer and portable builds on the same release page',
    body: 'Installer and portable ship together.',
    accent: 'sun' as const,
  },
];

export const stageModes = [
  {
    id: 'benchmark' as const,
    label: 'Benchmark',
    title: 'Compare resolvers like a modern product, not a throwback utility.',
    body: 'DNS Hop keeps the real test signals visible so you can spot fast-but-unstable servers before you switch.',
    points: [
      'Cached, uncached, and dotcom probes side by side',
      'Per-probe standard deviation on repeated runs',
      'DNSSEC visibility and protocol awareness',
    ],
    badge: 'Latency story',
  },
  {
    id: 'switch' as const,
    label: 'Switch',
    title: 'Move from result table to system DNS without leaving the app.',
    body: 'Shortlist candidates, sideline noise, then apply the resolver you actually trust instead of the one that merely won one pass.',
    points: [
      'Use selected DNS directly from the table',
      'Sidelined rows stay visible but skip future runs',
      'Status, protocol, and security stay readable',
    ],
    badge: 'Decision flow',
  },
  {
    id: 'portable' as const,
    label: 'Portable',
    title: 'Take the tool with you when you do not want an install.',
    body: 'The latest release ships both the installer and a portable zip, so testing on borrowed or locked-down systems stays simple.',
    points: [
      'Portable zip in every current release',
      'Release-aware About tab and update prompts',
      'CSV, JSON, and chart export built in',
    ],
    badge: 'Ship shape',
  },
];

export const featureCards = [
  {
    title: 'Readable response bars',
    body: 'The ranking table uses quick visual bars so you can read resolver behavior before you read every number.',
    accent: 'sky' as const,
  },
  {
    title: 'Windows-first control',
    body: 'DNS benchmarking, diagnostics, and switching live in one desktop workflow tuned for Windows instead of browser tabs and scripts.',
    accent: 'mint' as const,
  },
  {
    title: 'Release discipline',
    body: 'The app now exposes changelog data, update prompts, and parallel installer plus portable assets.',
    accent: 'sun' as const,
  },
  {
    title: 'No paywall positioning',
    body: 'DNS Hop is framed as an accessible tool, not a crippled teaser for a paid tier.',
    accent: 'sky' as const,
  },
  {
    title: 'Filtering that matches how people compare',
    body: 'Endpoint, provider, protocol, security, and active shortlist state can all be scanned without losing context.',
    accent: 'mint' as const,
  },
  {
    title: 'Export when the data matters',
    body: 'CSV, JSON, and chart copy let you take the benchmark outside the app when you need to publish or archive a run.',
    accent: 'sun' as const,
  },
];

export const workflowSteps = [
  {
    index: '01',
    title: 'Load the public list',
    body: 'Start broad.',
  },
  {
    index: '02',
    title: 'Run repeated probes',
    body: 'Check stability.',
  },
  {
    index: '03',
    title: 'Switch or export',
    body: 'Use it or save it.',
  },
];

export const faqItems = [
  {
    question: 'What makes DNS Hop different from older DNS benchmark tools?',
    answer:
      'The main difference is product clarity. DNS Hop combines modern UI, live release handling, portable builds, direct DNS switching, and richer probe visibility instead of acting like a raw benchmark dump.',
  },
  {
    question: 'Does it only benchmark one protocol?',
    answer:
      'No. The resolver list includes classic UDP/TCP entries plus encrypted endpoints such as DoH and DoT where available, and the table keeps the protocol visible.',
  },
  {
    question: 'Can I use it without installing anything?',
    answer:
      'Yes. Current releases ship a portable zip alongside the installer so you can run DNS Hop in environments where installing software is inconvenient.',
  },
  {
    question: 'Why show standard deviation now?',
    answer:
      'Average latency alone can hide unstable behavior. DNS Hop now surfaces per-probe deviation on repeated attempts so variance is visible instead of being buried.',
  },
];

export const fallbackRepo: GitHubRepo = {
  stargazers_count: 33,
  forks_count: 5,
  open_issues_count: 1,
  subscribers_count: 2,
  pushed_at: '2026-04-03T19:54:49Z',
  html_url: 'https://github.com/center2055/DNS-Hop',
  homepage: 'https://github.com/center2055/DNS-Hop/releases/latest',
  description: 'Fast Windows DNS benchmarking, diagnostics, and one-click switching without the paywall.',
};

export const fallbackRelease: GitHubRelease = {
  tag_name: 'v1.2',
  name: 'DNS Hop v1.2',
  html_url: 'https://github.com/center2055/DNS-Hop/releases/tag/v1.2',
  published_at: '2026-04-03T19:17:15Z',
  body: [
    '## DNS Hop v1.2',
    '',
    '- Added an About tab with GitHub, Discord, and Ko-Fi links',
    '- Added startup update checks and latest-release status inside the app',
    '- Normalized UI number formatting to English-style decimal dots',
    '- Added per-probe standard deviation metrics and portable release assets',
  ].join('\n'),
  assets: [
    {
      name: 'DNS-Hop-Setup-v1.2.exe',
      size: 16175443,
      download_count: 179,
      browser_download_url: 'https://github.com/center2055/DNS-Hop/releases/download/v1.2/DNS-Hop-Setup-v1.2.exe',
    },
    {
      name: 'DNS-Hop-Portable-v1.2.zip',
      size: 20324800,
      download_count: 62,
      browser_download_url: 'https://github.com/center2055/DNS-Hop/releases/download/v1.2/DNS-Hop-Portable-v1.2.zip',
    },
  ],
};
