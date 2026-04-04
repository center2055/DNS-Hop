import { useEffect, useState } from 'react';
import { fallbackRelease, fallbackRepo, type GitHubRelease, type GitHubRepo } from '../data/site';

type SnapshotState = {
  repo: GitHubRepo;
  release: GitHubRelease;
  loading: boolean;
  error: string | null;
  isFallback: boolean;
};

const defaultState: SnapshotState = {
  repo: fallbackRepo,
  release: fallbackRelease,
  loading: true,
  error: null,
  isFallback: true,
};

async function loadJson<T>(url: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(url, {
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
        const [repo, release] = await Promise.all([
          loadJson<GitHubRepo>('https://api.github.com/repos/center2055/DNS-Hop', controller.signal),
          loadJson<GitHubRelease>('https://api.github.com/repos/center2055/DNS-Hop/releases/latest', controller.signal),
        ]);

        if (isDisposed) {
          return;
        }

        setState({
          repo,
          release,
          loading: false,
          error: null,
          isFallback: false,
        });
      } catch (error) {
        if (isDisposed || controller.signal.aborted) {
          return;
        }

        setState({
          repo: fallbackRepo,
          release: fallbackRelease,
          loading: false,
          error: error instanceof Error ? error.message : 'GitHub snapshot unavailable',
          isFallback: true,
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
