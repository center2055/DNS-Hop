import { useEffect, useState } from 'react';
import { fallbackRelease, fallbackRepo, type GitHubRelease, type GitHubRepo } from '../data/site';

type SnapshotState = {
  repo: GitHubRepo;
  release: GitHubRelease;
  totalDownloads: number;
  loading: boolean;
  error: string | null;
  isFallback: boolean;
  fetchedAt: string | null;
};

function sumDownloads(releases: GitHubRelease[]) {
  return releases.reduce((total, release) => {
    return total + release.assets.reduce((sum, asset) => sum + asset.download_count, 0);
  }, 0);
}

const defaultState: SnapshotState = {
  repo: fallbackRepo,
  release: fallbackRelease,
  totalDownloads: sumDownloads([fallbackRelease]),
  loading: true,
  error: null,
  isFallback: true,
  fetchedAt: null,
};

async function loadJson<T>(url: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(url, {
    cache: 'no-store',
    headers: {
      Accept: 'application/vnd.github+json',
    },
    signal,
  });

  if (!response.ok) {
    throw new Error(`GitHub request failed with ${response.status}`);
  }

  return (await response.json()) as T;
}

export function useDnsHopSnapshot() {
  const [state, setState] = useState<SnapshotState>(defaultState);

  useEffect(() => {
    const controller = new AbortController();
    let isDisposed = false;

    async function run() {
      try {
        const fetchedAt = new Date().toISOString();
        const [repo, releases] = await Promise.all([
          loadJson<GitHubRepo>('https://api.github.com/repos/center2055/DNS-Hop', controller.signal),
          loadJson<GitHubRelease[]>(
            'https://api.github.com/repos/center2055/DNS-Hop/releases?per_page=100',
            controller.signal,
          ),
        ]);

        if (isDisposed) {
          return;
        }

        const published = releases
          .filter((r) => Boolean(r.published_at))
          .sort((a, b) => new Date(b.published_at).getTime() - new Date(a.published_at).getTime());
        const latest = published[0] ?? fallbackRelease;

        setState({
          repo,
          release: latest,
          totalDownloads: sumDownloads(releases),
          loading: false,
          error: null,
          isFallback: false,
          fetchedAt,
        });
      } catch (error) {
        if (isDisposed || controller.signal.aborted) {
          return;
        }

        setState({
          repo: fallbackRepo,
          release: fallbackRelease,
          totalDownloads: sumDownloads([fallbackRelease]),
          loading: false,
          error: error instanceof Error ? error.message : 'GitHub snapshot unavailable',
          isFallback: true,
          fetchedAt: new Date().toISOString(),
        });
      }
    }

    run();

    return () => {
      isDisposed = true;
      controller.abort();
    };
  }, []);

  return state;
}
