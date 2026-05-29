import { useEffect, useState } from 'react';
import dashboardImage from './assets/dns-hop-dashboard.png';
import brandMark from './assets/dnshop-mark.png';
import { ImprintPage, PrivacyPage } from './Legal';
import { faqItems, featureCards, workflowSteps, type GitHubAsset } from './data/site';
import { useDnsHopSnapshot } from './hooks/useDnsHopSnapshot';

const REPO_URL = 'https://github.com/center2055/DNS-Hop';
const RELEASES_URL = 'https://github.com/center2055/DNS-Hop/releases';
const DISCORD_URL = 'https://discord.gg/y3MVspPzKQ';
const KOFI_URL = 'https://ko-fi.com/center2055';

function formatCompactNumber(value: number) {
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
}

function formatBytes(bytes: number) {
  return new Intl.NumberFormat('en', { maximumFractionDigits: 0 }).format(bytes / (1024 * 1024));
}

function assetKind(asset: GitHubAsset) {
  const name = asset.name.toLowerCase();
  if (name.includes('portable')) return 'Windows portable';
  if (name.endsWith('.appimage')) return 'Linux AppImage';
  if (name.endsWith('.exe')) return 'Windows installer';
  return 'Release asset';
}

type Route = 'home' | 'privacy' | 'imprint';

function resolveRoute(): Route {
  const hash = window.location.hash;
  if (hash === '#/privacy') return 'privacy';
  if (hash === '#/imprint') return 'imprint';
  return 'home';
}

function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(resolveRoute);
  useEffect(() => {
    const onHash = () => {
      setRoute(resolveRoute());
      // Route hashes (#/...) jump to top; in-page anchors keep native behaviour.
      if (window.location.hash.startsWith('#/')) {
        window.scrollTo({ top: 0 });
      }
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  return route;
}

function GitHubMark() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" width="16" height="16">
      <path
        fill="currentColor"
        d="M12 .5a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.04c-3.34.73-4.04-1.42-4.04-1.42-.55-1.38-1.33-1.75-1.33-1.75-1.09-.73.08-.72.08-.72 1.2.09 1.83 1.22 1.83 1.22 1.08 1.82 2.82 1.3 3.5.99.11-.76.42-1.3.76-1.6-2.66-.3-5.47-1.31-5.47-5.86 0-1.3.47-2.36 1.24-3.2-.13-.3-.54-1.5.12-3.13 0 0 1.01-.32 3.3 1.22a11.67 11.67 0 0 1 6 0c2.28-1.54 3.29-1.22 3.29-1.22.67 1.63.25 2.83.13 3.13.77.84 1.24 1.9 1.24 3.2 0 4.56-2.81 5.55-5.49 5.85.43.37.82 1.1.82 2.22v3.29c0 .32.21.7.83.58A12 12 0 0 0 12 .5Z"
      />
    </svg>
  );
}

function SiteHeader({ releaseTag }: { releaseTag: string }) {
  return (
    <header className="site-header">
      <div className="container">
        <a className="brand" href="#/" aria-label="DNS Hop home">
          <img className="brand-mark" src={brandMark} alt="" width="28" height="28" />
          <span className="brand-title">DNS Hop</span>
        </a>
        <nav className="site-nav" aria-label="Primary">
          <a href="#features">Features</a>
          <a href="#download">Download</a>
          <a href="#faq">FAQ</a>
        </nav>
        <div className="header-actions">
          <a className="header-ghost" href={REPO_URL} target="_blank" rel="noreferrer">
            <GitHubMark />
            <span>GitHub</span>
          </a>
          <a className="btn btn-primary" href={RELEASES_URL} target="_blank" rel="noreferrer">
            Download {releaseTag}
          </a>
        </div>
      </div>
    </header>
  );
}

function SiteFooter() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-top">
          <div className="footer-brand">
            <a className="brand" href="#/" aria-label="DNS Hop home">
              <img className="brand-mark" src={brandMark} alt="" width="28" height="28" />
              <span className="brand-title">DNS Hop</span>
            </a>
            <p>A free, open-source DNS benchmark and switcher for Windows and Linux.</p>
          </div>
          <div className="footer-col">
            <h4>Product</h4>
            <a href={RELEASES_URL} target="_blank" rel="noreferrer">Download</a>
            <a href={REPO_URL} target="_blank" rel="noreferrer">Source</a>
            <a href={RELEASES_URL} target="_blank" rel="noreferrer">Changelog</a>
          </div>
          <div className="footer-col">
            <h4>Community</h4>
            <a href={DISCORD_URL} target="_blank" rel="noreferrer">Discord</a>
            <a href={KOFI_URL} target="_blank" rel="noreferrer">Ko-fi</a>
            <a href={`${REPO_URL}/issues`} target="_blank" rel="noreferrer">Report an issue</a>
          </div>
          <div className="footer-col">
            <h4>Legal</h4>
            <a href="#/privacy">Privacy</a>
            <a href="#/imprint">Imprint</a>
            <a href={`${REPO_URL}/blob/main/LICENSE`} target="_blank" rel="noreferrer">License</a>
          </div>
        </div>
        <div className="footer-bottom">
          <span>© 2026 DNS Hop. Open source.</span>
          <span>Not affiliated with any DNS provider.</span>
        </div>
      </div>
    </footer>
  );
}

function HomePage({ snapshot }: { snapshot: ReturnType<typeof useDnsHopSnapshot> }) {
  const { repo, release, totalDownloads } = snapshot;
  const [openFaq, setOpenFaq] = useState(0);

  const installer = release.assets.find((a) => a.name.toLowerCase().endsWith('.exe'));
  const portable = release.assets.find((a) => a.name.toLowerCase().includes('portable'));
  const appImage = release.assets.find((a) => a.name.toLowerCase().endsWith('.appimage'));
  const downloads = [installer, portable, appImage].filter(Boolean) as GitHubAsset[];

  return (
    <main>
      <section className="hero">
        <div className="container">
          <div className="hero-copy">
            <span className="eyebrow">Benchmark · Profile · Switch</span>
            <h1>A faster way to find and apply the right DNS resolver.</h1>
            <p className="lead">
              DNS Hop benchmarks public resolvers across UDP, DoH and DoT, then lets you apply the
              winner, or a saved profile, to your system in one click. Native installer, portable
              build and Linux AppImage from the same release.
            </p>
            <div className="hero-actions">
              <a className="btn btn-primary" href={RELEASES_URL} target="_blank" rel="noreferrer">
                Download {release.tag_name}
              </a>
              <a className="btn btn-secondary" href="#features">See what it does</a>
            </div>
            <div className="hero-metrics">
              <div className="metric">
                <span className="metric-value">{formatCompactNumber(repo.stargazers_count)}</span>
                <span className="metric-label">GitHub stars</span>
              </div>
              <div className="metric">
                <span className="metric-value">{formatCompactNumber(totalDownloads)}</span>
                <span className="metric-label">Downloads</span>
              </div>
              <div className="metric">
                <span className="metric-value">{release.tag_name}</span>
                <span className="metric-label">Latest release</span>
              </div>
              <div className="metric">
                <span className="metric-value">2</span>
                <span className="metric-label">Platforms</span>
              </div>
            </div>
          </div>
          <div className="shot">
            <div className="shot-bar" aria-hidden="true">
              <span className="shot-dot" />
              <span className="shot-dot" />
              <span className="shot-dot" />
            </div>
            <img src={dashboardImage} alt="DNS Hop application home screen" loading="eager" decoding="async" />
          </div>
        </div>
      </section>

      <section className="section" id="features">
        <div className="container">
          <div className="section-head">
            <h2>Everything in one desktop app</h2>
            <p>No browser tabs, no scripts. Benchmarking, diagnostics and switching in one window.</p>
          </div>
          <div className="feature-grid">
            {featureCards.map((card) => (
              <article className="feature" key={card.title}>
                <h3>{card.title}</h3>
                <p>{card.body}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section" id="how">
        <div className="container">
          <div className="section-head">
            <h2>How it works</h2>
            <p>Three steps from a fresh list of resolvers to a verified system DNS.</p>
          </div>
          <div className="steps">
            {workflowSteps.map((step) => (
              <div className="step" key={step.index}>
                <span className="step-num">{step.index}</span>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section" id="download">
        <div className="container">
          <div className="section-head">
            <h2>Download {release.tag_name}</h2>
            <p>Self-contained builds, no runtime to install.</p>
          </div>
          <div className="downloads">
            {downloads.map((asset) => (
              <article className="dl-card" key={asset.name}>
                <span className="dl-kind">{assetKind(asset)}</span>
                <span className="dl-name">{asset.name}</span>
                <a className="btn btn-secondary" href={asset.browser_download_url} target="_blank" rel="noreferrer">
                  Download
                </a>
                <div className="dl-meta">
                  <span>{formatBytes(asset.size)} MB</span>
                  <span>{formatCompactNumber(asset.download_count)} downloads</span>
                </div>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section" id="faq">
        <div className="container">
          <div className="section-head">
            <h2>Frequently asked</h2>
          </div>
          <div className="faq">
            {faqItems.map((item, index) => {
              const isOpen = openFaq === index;
              return (
                <div className="faq-item" key={item.question}>
                  <button
                    className="faq-q"
                    type="button"
                    aria-expanded={isOpen}
                    onClick={() => setOpenFaq(isOpen ? -1 : index)}
                  >
                    <span>{item.question}</span>
                    <span className="faq-toggle" aria-hidden="true">{isOpen ? '−' : '+'}</span>
                  </button>
                  {isOpen ? <p className="faq-a">{item.answer}</p> : null}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="cta">
        <div className="container">
          <h2>Get DNS Hop {release.tag_name}</h2>
          <p>Free and open source. Pick the build for your platform and start benchmarking.</p>
          <div className="cta-actions">
            <a className="btn btn-primary" href={RELEASES_URL} target="_blank" rel="noreferrer">
              Download
            </a>
            <a className="btn btn-secondary" href={REPO_URL} target="_blank" rel="noreferrer">
              View source
            </a>
          </div>
        </div>
      </section>
    </main>
  );
}

function App() {
  const route = useHashRoute();
  const snapshot = useDnsHopSnapshot();

  return (
    <>
      <SiteHeader releaseTag={snapshot.release.tag_name} />
      {route === 'privacy' ? (
        <PrivacyPage />
      ) : route === 'imprint' ? (
        <ImprintPage />
      ) : (
        <HomePage snapshot={snapshot} />
      )}
      <SiteFooter />
    </>
  );
}

export default App;
