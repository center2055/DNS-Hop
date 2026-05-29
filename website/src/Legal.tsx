// Legal pages for DNS Hop. German Impressum (§5 DDG) + GDPR privacy policy.
//
// NOTE FOR THE MAINTAINER: these are working templates, not legal advice. Have
// them reviewed if in doubt.

const CONTACT_EMAIL = 'jakob.rudolph1337@gmail.com';
const OPERATOR = 'Jakob Rudolph';
const ADDRESS_STREET = 'Niederkirchnerstraße 16';
const ADDRESS_CITY = '04107 Leipzig, Germany';
const LAST_UPDATED = '29 May 2026';

function AddressBlock() {
  return (
    <>
      {OPERATOR}
      <br />
      {ADDRESS_STREET}
      <br />
      {ADDRESS_CITY}
    </>
  );
}

function BackLink() {
  return (
    <a className="legal-back" href="#/">
      Back to DNS Hop
    </a>
  );
}

export function ImprintPage() {
  return (
    <section className="legal">
      <div className="container">
        <BackLink />
        <h1>Imprint / Impressum</h1>
        <p className="legal-updated">Information according to § 5 DDG (German Digital Services Act).</p>

        <h2>Operator</h2>
        <p>
          <AddressBlock />
        </p>

        <h2>Contact</h2>
        <p>
          Email: <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
        </p>

        <h2>Responsible for content (§ 18 Abs. 2 MStV)</h2>
        <p>{OPERATOR}, address as above.</p>

        <h2>Nature of the project</h2>
        <p>
          DNS Hop is a free, open-source, non-commercial software project. This website exists to
          document the project and link to its releases. No goods or services are sold here.
        </p>

        <h2>EU dispute resolution</h2>
        <p>
          We are neither willing nor obliged to participate in dispute resolution proceedings before
          a consumer arbitration board.
        </p>

        <h2>Liability for content</h2>
        <p>
          As a service provider we are responsible for our own content on these pages in accordance
          with general law. We are not obliged to monitor transmitted or stored third-party
          information, or to investigate circumstances that indicate illegal activity.
        </p>

        <h2>Liability for links</h2>
        <p>
          This site contains links to external websites over whose content we have no control. We
          accept no liability for that third-party content; the respective provider or operator of
          those pages is always responsible for their content.
        </p>

        <h2>Copyright</h2>
        <p>
          The DNS Hop source code is published under its repository license on GitHub. Trademarks and
          product names of third parties (e.g. Windows, Cloudflare, Google) belong to their
          respective owners and are used for identification only.
        </p>
      </div>
    </section>
  );
}

export function PrivacyPage() {
  return (
    <section className="legal">
      <div className="container">
        <BackLink />
        <h1>Privacy Policy / Datenschutzerklärung</h1>
        <p className="legal-updated">Last updated: {LAST_UPDATED}</p>

        <h2>Short version</h2>
        <p>
          This website sets no cookies, runs no analytics, and embeds no trackers or third-party
          fonts. It is a static page hosted on GitHub Pages. The only personal data processed is what
          your browser necessarily sends when requesting any web page, plus one optional request to
          GitHub's public API to show live release information.
        </p>

        <h2>Controller</h2>
        <p>
          <AddressBlock />
          <br />
          Email: <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
        </p>

        <h2>Hosting (GitHub Pages)</h2>
        <p>
          This site is hosted on GitHub Pages, a service of GitHub, Inc. (USA). When you open the
          site, GitHub automatically processes connection data (your IP address, the requested file,
          and the date and time) in server log files. This is technically necessary
          to deliver the page and to maintain security and stability. Legal basis: Art. 6(1)(f) GDPR
          (legitimate interest in secure, reliable delivery). See{' '}
          <a href="https://docs.github.com/site-policy/privacy-policies/github-privacy-statement" target="_blank" rel="noreferrer">
            GitHub's Privacy Statement
          </a>
          .
        </p>

        <h2>Live release data (GitHub API)</h2>
        <p>
          To display the current version, asset list and download counts, the page makes a request
          from your browser to <code>api.github.com</code>. This transmits your IP address to GitHub
          as part of that request. If you do not want this, you can block the request; the rest of
          the page still works. Legal basis: Art. 6(1)(f) GDPR.
        </p>

        <h2>Fonts</h2>
        <p>
          The Inter typeface is bundled with the site and served from the same origin. No request is
          made to Google Fonts or any other third-party font service, so no data is shared with them.
        </p>

        <h2>Cookies, analytics, tracking</h2>
        <p>None. The site stores nothing on your device and does not profile visitors.</p>

        <h2>External links</h2>
        <p>
          Download links point to GitHub Releases, and the footer links to GitHub, Discord and Ko-fi.
          These are operated by third parties under their own privacy policies; this policy does not
          cover them.
        </p>

        <h2>Your rights under the GDPR</h2>
        <p>You have the right to:</p>
        <ul>
          <li>access the data we hold about you (Art. 15),</li>
          <li>rectification (Art. 16) and erasure (Art. 17),</li>
          <li>restriction of processing (Art. 18),</li>
          <li>data portability (Art. 20),</li>
          <li>object to processing (Art. 21).</li>
        </ul>
        <p>
          You also have the right to lodge a complaint with a data protection supervisory authority
          (Art. 77 GDPR). To exercise any of these, contact us at the email above.
        </p>
      </div>
    </section>
  );
}
