import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { startTransition, useState, type MouseEvent } from 'react';
import dashboardImage from './assets/dns-hop-dashboard.png';
import brandMark from './assets/dnshop-mark.png';
import {
  faqItems,
  heroSignals,
  navItems,
  stageModes,
  workflowSteps,
  type Accent,
  type GitHubAsset,
  type StageModeId,
} from './data/site';
import { useDnsHopSnapshot } from './hooks/useDnsHopSnapshot';

function formatCompactNumber(value: number) {
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
}

function formatBytes(bytes: number) {
  return new Intl.NumberFormat('en', {
    maximumFractionDigits: 1,
  }).format(bytes / (1024 * 1024));
}

function formatDate(dateValue: string) {
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(dateValue));
}

function formatDateTime(dateValue: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(dateValue));
}

function updateSpotlight(event: MouseEvent<HTMLElement>) {
  const rect = event.currentTarget.getBoundingClientRect();
  event.currentTarget.style.setProperty('--spot-x', `${event.clientX - rect.left}px`);
  event.currentTarget.style.setProperty('--spot-y', `${event.clientY - rect.top}px`);
  event.currentTarget.style.setProperty('--spot-opacity', '1');
}

function resetSpotlight(event: MouseEvent<HTMLElement>) {
  event.currentTarget.style.setProperty('--spot-opacity', '0');
}

function assetKind(asset: GitHubAsset) {
  const lowerName = asset.name.toLowerCase();

  if (lowerName.includes('portable')) {
    return 'Portable build';
  }

  if (lowerName.endsWith('.exe')) {
    return 'Windows installer';
  }

  return 'Release asset';
}

function SocialIcon({ type }: { type: 'github' | 'discord' | 'kofi' }) {
  if (type === 'github') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true" width="16" height="16">
        <path
          fill="currentColor"
          d="M12 .5a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.04c-3.34.73-4.04-1.42-4.04-1.42-.55-1.38-1.33-1.75-1.33-1.75-1.09-.73.08-.72.08-.72 1.2.09 1.83 1.22 1.83 1.22 1.08 1.82 2.82 1.3 3.5.99.11-.76.42-1.3.76-1.6-2.66-.3-5.47-1.31-5.47-5.86 0-1.3.47-2.36 1.24-3.2-.13-.3-.54-1.5.12-3.13 0 0 1.01-.32 3.3 1.22a11.67 11.67 0 0 1 6 0c2.28-1.54 3.29-1.22 3.29-1.22.67 1.63.25 2.83.13 3.13.77.84 1.24 1.9 1.24 3.2 0 4.56-2.81 5.55-5.49 5.85.43.37.82 1.1.82 2.22v3.29c0 .32.21.7.83.58A12 12 0 0 0 12 .5Z"
        />
      </svg>
    );
  }

  if (type === 'discord') {
    return (
      <svg viewBox="0 0 64 48" aria-hidden="true" width="16" height="16">
        <path
          fill="currentColor"
          d="M40.575 0C39.9562 1.09866 39.4006 2.2352 38.8954 3.397C34.0967 2.67719 29.2096 2.67719 24.3982 3.397C23.9057 2.2352 23.3374 1.09866 22.7186 0C18.2104 0.770324 13.8157 2.12155 9.64839 4.02841C1.38951 16.2652 -0.845688 28.1863 0.265599 39.9432C5.10222 43.517 10.5197 46.2447 16.2909 47.9874C17.5916 46.2447 18.7407 44.3883 19.7257 42.4562C17.8568 41.7616 16.0509 40.8903 14.3208 39.88C14.7755 39.5517 15.2175 39.2107 15.6468 38.8824C25.7873 43.6559 37.5316 43.6559 47.6847 38.8824C48.1141 39.236 48.5561 39.577 49.0107 39.88C47.2806 40.9029 45.4748 41.7616 43.5931 42.4688C44.5781 44.4009 45.7273 46.2573 47.028 48C52.7991 46.2573 58.2167 43.5422 63.0533 39.9684C64.3666 26.3299 60.8055 14.5099 53.6452 4.04104C49.4905 2.13418 45.0959 0.782952 40.5876 0.0252565L40.575 0ZM21.1401 32.7072C18.0209 32.7072 15.4321 29.8785 15.4321 26.3804C15.4321 22.8824 17.9199 20.041 21.1275 20.041C24.3351 20.041 26.886 22.895 26.8354 26.3804C26.7849 29.8658 24.3224 32.7072 21.1401 32.7072ZM42.1788 32.7072C39.047 32.7072 36.4834 29.8785 36.4834 26.3804C36.4834 22.8824 38.9712 20.041 42.1788 20.041C45.3864 20.041 47.9246 22.895 47.8741 26.3804C47.8236 29.8658 45.3611 32.7072 42.1788 32.7072Z"
        />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" width="16" height="16">
      <path
        fill="currentColor"
        d="M7 4h10a4 4 0 0 1 4 4v5a4 4 0 0 1-4 4h-2.1l-2.33 2.34a1 1 0 0 1-1.41 0L8.83 17H7a4 4 0 0 1-4-4V8a4 4 0 0 1 4-4Zm1.6 5.4a1.6 1.6 0 1 0 0 3.2 1.6 1.6 0 0 0 0-3.2Zm6.8 0a1.6 1.6 0 1 0 0 3.2 1.6 1.6 0 0 0 0-3.2Z"
      />
    </svg>
  );
}

function FeatureCard({
  accent,
  kicker,
  title,
  body,
  reducedMotion,
  index,
}: {
  accent: Accent;
  kicker: string;
  title: string;
  body: string;
  reducedMotion: boolean;
  index: number;
}) {
  return (
    <motion.article
      className={`feature-card accent-${accent}`}
      initial={reducedMotion ? false : { opacity: 0, y: 28 }}
      whileInView={reducedMotion ? undefined : { opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.5, delay: reducedMotion ? 0 : index * 0.06, ease: [0.22, 1, 0.36, 1] }}
      onMouseMove={updateSpotlight}
      onMouseLeave={resetSpotlight}
    >
      <span className="feature-topline">{kicker}</span>
      <h3>{title}</h3>
      <p>{body}</p>
    </motion.article>
  );
}

function App() {
  const reducedMotion = useReducedMotion() ?? false;
  const { repo, release, loading, error, isFallback, fetchedAt } = useDnsHopSnapshot();
  const [activeMode, setActiveMode] = useState<StageModeId>('benchmark');
  const [openFaq, setOpenFaq] = useState(0);

  const activeStage = stageModes.find((mode) => mode.id === activeMode) ?? stageModes[0];
  const totalDownloads = release.assets.reduce((sum, asset) => sum + asset.download_count, 0);
  const installerAsset = release.assets.find((asset) => asset.name.toLowerCase().endsWith('.exe')) ?? release.assets[0];
  const portableAsset = release.assets.find((asset) => asset.name.toLowerCase().includes('portable')) ?? release.assets[1];
  const featuredAssets = [installerAsset, portableAsset].filter((asset, index, assets): asset is GitHubAsset => {
    return Boolean(asset) && assets.findIndex((candidate) => candidate?.name === asset?.name) === index;
  });
  const repeatedMarquee = [
    'installer + portable',
    'dnssec visibility',
    'doH + doT aware',
    'std deviation on repeated probes',
    'filter, sideline, switch',
    'csv + json + chart export',
    'github-linked updates',
    'windows-first utility',
  ];

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="DNS Hop home">
          <img className="brand-mark" src={brandMark} alt="" width="34" height="34" />
          <span className="brand-copy">
            <span className="brand-title">DNS Hop</span>
            <span className="brand-subtitle">Windows DNS benchmark with product polish</span>
          </span>
        </a>

        <nav className="site-nav" aria-label="Primary">
          {navItems.map((item) => (
            <a key={item.href} href={item.href}>
              {item.label}
            </a>
          ))}
        </nav>

        <div className="header-actions">
          <a className="header-action" href="https://github.com/center2055/DNS-Hop" target="_blank" rel="noreferrer">
            <SocialIcon type="github" />
            <span>GitHub</span>
          </a>
          <a className="header-action primary" href={release.html_url} target="_blank" rel="noreferrer">
            <span>Download {release.tag_name}</span>
          </a>
        </div>
      </header>

      <main id="top">
        <section className="hero">
          <motion.div
            className="hero-copy"
            initial={reducedMotion ? false : { opacity: 0, y: 24 }}
            animate={reducedMotion ? undefined : { opacity: 1, y: 0 }}
            transition={{ duration: 0.75, ease: [0.22, 1, 0.36, 1] }}
          >
            <span className="eyebrow">Benchmark. Compare. Switch.</span>
            <h1>DNS tooling that feels current instead of inherited.</h1>
            <p className="hero-intro">
              DNS Hop turns resolver testing into a cleaner Windows workflow: live ranking tables, visible probe
              behavior, direct switching, portable releases, and enough polish that you actually want to keep it open.
            </p>

            <div className="hero-actions">
              <a className="button primary" href={release.html_url} target="_blank" rel="noreferrer">
                Get {release.tag_name}
              </a>
              <a className="button secondary" href="#release">
                See live release data
              </a>
            </div>

            <div className="hero-metrics" aria-label="Live DNS Hop metrics">
              <div className="hero-metric">
                <span>Stars</span>
                <strong>{formatCompactNumber(repo.stargazers_count)}</strong>
              </div>
              <div className="hero-metric">
                <span>Total release downloads</span>
                <strong>{formatCompactNumber(totalDownloads)}</strong>
              </div>
              <div className="hero-metric">
                <span>Latest release</span>
                <strong>{release.tag_name}</strong>
              </div>
              <div className="hero-metric">
                <span>Assets in latest</span>
                <strong>{release.assets.length}</strong>
              </div>
            </div>

            <div className="status-line">
              <span className={`status-dot ${isFallback ? 'fallback' : ''}`} />
              <span>
                {loading
                  ? 'Fetching live GitHub snapshot'
                  : error
                    ? `Showing fallback release data (${error})`
                    : `Live GitHub data fetched ${fetchedAt ? formatDateTime(fetchedAt) : 'just now'}`}
              </span>
            </div>
          </motion.div>

          <motion.aside
            className="hero-stage"
            initial={reducedMotion ? false : { opacity: 0, y: 24 }}
            animate={reducedMotion ? undefined : { opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: reducedMotion ? 0 : 0.08, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="stage-topline">
              <span className="stage-label">Product preview</span>
              <span className="stage-release-pill">{activeStage.badge}</span>
            </div>

            <div className="mode-switcher" role="tablist" aria-label="DNS Hop focus modes">
              {stageModes.map((mode) => (
                <button
                  key={mode.id}
                  type="button"
                  role="tab"
                  aria-selected={mode.id === activeMode}
                  className={mode.id === activeMode ? 'is-active' : ''}
                  onClick={() => {
                    startTransition(() => {
                      setActiveMode(mode.id);
                    });
                  }}
                >
                  {mode.label}
                </button>
              ))}
            </div>

            <div className="stage-screen">
              <img src={dashboardImage} alt="DNS Hop app dashboard screenshot" loading="eager" decoding="async" />
              <div className="floating-stat">
                <span>{activeStage.label}</span>
                <strong>{release.tag_name}</strong>
                <span>Published {formatDate(release.published_at)}</span>
              </div>
              <div className="floating-note">
                <span>Latest release assets</span>
                <strong>{release.assets.map((asset) => assetKind(asset)).join(' + ')}</strong>
              </div>
            </div>

            <AnimatePresence mode="wait">
              <motion.div
                key={activeStage.id}
                className="stage-detail"
                initial={reducedMotion ? false : { opacity: 0, y: 16 }}
                animate={reducedMotion ? undefined : { opacity: 1, y: 0 }}
                exit={reducedMotion ? undefined : { opacity: 0, y: -10 }}
                transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
              >
                <h2>{activeStage.title}</h2>
                <p>{activeStage.body}</p>
                <ul className="stage-points">
                  {activeStage.points.map((point) => (
                    <li key={point}>{point}</li>
                  ))}
                </ul>
              </motion.div>
            </AnimatePresence>
          </motion.aside>
        </section>

        <section className="marquee" aria-label="DNS Hop capabilities">
          <div className="marquee-track">
            {repeatedMarquee.concat(repeatedMarquee).map((item, index) => (
              <span key={`${item}-${index}`} className="marquee-pill">
                {item}
              </span>
            ))}
          </div>
        </section>

        <section className="section section-grid compact-section" id="why">
          <div className="section-heading">
            <span className="eyebrow">Why it hits</span>
            <h2>Why DNS Hop.</h2>
          </div>

          <div className="signal-grid">
            {heroSignals.map((card, index) => (
              <FeatureCard
                key={card.title}
                accent={card.accent}
                kicker={card.kicker}
                title={card.title}
                body={card.body}
                reducedMotion={reducedMotion}
                index={index}
              />
            ))}
          </div>
        </section>

        <section className="section section-grid compact-section" id="workflow">
          <div className="section-heading">
            <span className="eyebrow">Workflow</span>
            <h2>How it works.</h2>
          </div>

          <div className="workflow-grid">
            {workflowSteps.map((step, index) => (
              <motion.article
                key={step.index}
                className={`workflow-card accent-${index % 3 === 0 ? 'sky' : index % 3 === 1 ? 'mint' : 'sun'}`}
                initial={reducedMotion ? false : { opacity: 0, y: 24 }}
                whileInView={reducedMotion ? undefined : { opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.25 }}
                transition={{ duration: 0.45, delay: reducedMotion ? 0 : index * 0.06, ease: [0.22, 1, 0.36, 1] }}
                onMouseMove={updateSpotlight}
                onMouseLeave={resetSpotlight}
              >
                <span className="workflow-index">{step.index}</span>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </motion.article>
            ))}
          </div>
        </section>

        <section className="section section-grid release-section" id="release">
          <div className="section-heading">
            <span className="eyebrow">Download</span>
            <h2>Grab the current build.</h2>

            <div className="section-actions">
              <a
                className="button primary"
                href={installerAsset?.browser_download_url ?? release.html_url}
                target="_blank"
                rel="noreferrer"
              >
                Download installer
              </a>
              <a
                className="button secondary"
                href={portableAsset?.browser_download_url ?? release.html_url}
                target="_blank"
                rel="noreferrer"
              >
                Get portable zip
              </a>
            </div>
          </div>

          <div className="release-grid">
            <div className="release-assets">
              {featuredAssets.map((asset) => (
                <article
                  key={asset.name}
                  className="release-card release-asset"
                  onMouseMove={updateSpotlight}
                  onMouseLeave={resetSpotlight}
                >
                  <div className="release-asset-head">
                    <div>
                      <span className="feature-topline">{assetKind(asset)}</span>
                      <h4>{asset.name}</h4>
                    </div>
                    <a className="button secondary" href={asset.browser_download_url} target="_blank" rel="noreferrer">
                      Download
                    </a>
                  </div>
                  <div className="release-asset-meta">
                    <span>{formatCompactNumber(asset.download_count)} downloads</span>
                    <span>{formatBytes(asset.size)} MB</span>
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="section section-grid" id="faq">
          <div className="section-heading">
            <span className="eyebrow">FAQ</span>
            <h2>Short answers for the obvious questions.</h2>
          </div>

          <div className="faq-shell">
            {faqItems.map((item, index) => {
              const isOpen = openFaq === index;

              return (
                <motion.article
                  key={item.question}
                  className="faq-card"
                  initial={reducedMotion ? false : { opacity: 0, y: 18 }}
                  whileInView={reducedMotion ? undefined : { opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.3 }}
                  transition={{ duration: 0.38, delay: reducedMotion ? 0 : index * 0.05, ease: [0.22, 1, 0.36, 1] }}
                >
                  <span className="faq-topline">Question {String(index + 1).padStart(2, '0')}</span>
                  <button
                    className="faq-button"
                    type="button"
                    aria-expanded={isOpen}
                    onClick={() => setOpenFaq(isOpen ? -1 : index)}
                  >
                    <span className="faq-question">{item.question}</span>
                    <span className="faq-toggle">{isOpen ? '−' : '+'}</span>
                  </button>

                  <AnimatePresence initial={false}>
                    {isOpen ? (
                      <motion.p
                        className="faq-answer"
                        initial={reducedMotion ? false : { height: 0, opacity: 0 }}
                        animate={reducedMotion ? undefined : { height: 'auto', opacity: 1 }}
                        exit={reducedMotion ? undefined : { height: 0, opacity: 0 }}
                        transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
                      >
                        {item.answer}
                      </motion.p>
                    ) : null}
                  </AnimatePresence>
                </motion.article>
              );
            })}
          </div>
        </section>

        <section className="section cta-shell">
          <article className="cta-card" onMouseMove={updateSpotlight} onMouseLeave={resetSpotlight}>
            <div>
              <span className="eyebrow">Take it live</span>
              <h2>Open the release, grab the right build, and benchmark your next resolver set.</h2>
              <p>
                DNS Hop now ships with an installer, a portable zip, and an interface that is finally worth showing
                publicly.
              </p>
            </div>

            <div className="cta-actions">
              <a className="button primary" href={release.html_url} target="_blank" rel="noreferrer">
                Download {release.tag_name}
              </a>
              <a className="button secondary" href="https://github.com/center2055/DNS-Hop" target="_blank" rel="noreferrer">
                Source
              </a>
            </div>
          </article>
        </section>
      </main>

      <footer className="footer">
        <a className="brand" href="#top" aria-label="Back to top">
          <img className="brand-mark" src={brandMark} alt="" width="34" height="34" />
          <span className="brand-copy">
            <span className="brand-title">DNS Hop</span>
            <span className="brand-subtitle">Fast Windows DNS benchmarking without the paywall</span>
          </span>
        </a>

        <div className="footer-links">
          <a href="https://github.com/center2055/DNS-Hop" target="_blank" rel="noreferrer">
            GitHub
          </a>
          <a href="https://discord.gg/y3MVspPzKQ" target="_blank" rel="noreferrer">
            Discord
          </a>
          <a href="https://ko-fi.com/center2055" target="_blank" rel="noreferrer">
            Ko-Fi
          </a>
        </div>
      </footer>
    </div>
  );
}

export default App;
