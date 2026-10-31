"use client";

import * as React from "react";

export type ChartStatus = "ready" | "loading" | "error" | "empty";

export const DAY_MS = 86_400_000;
export const EASE = "cubic-bezier(0.16, 1, 0.3, 1)";
export const TRACK = "var(--spectrum-track, rgba(120, 120, 120, 0.12))";
export const seriesVarsClassName = "spectrum-series-vars";

export function formatCount(n: number, decimals: number = 0): string {
  if (n >= 1_000_000) {
    return (n / 1_000_000).toFixed(decimals) + "M";
  }
  if (n >= 1_000) {
    return (n / 1_000).toFixed(decimals) + "k";
  }
  return n.toLocaleString();
}

export function intensityColor(ratio: number, hue: string): string {
  if (ratio <= 0) return TRACK;
  const pct = Math.max(20, Math.min(100, Math.round(ratio * 100)));
  return `color-mix(in srgb, ${hue} ${pct}%, transparent)`;
}

export function mulberry32(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function Keyframes() {
  return (
    <style>{`
      @keyframes spectrum-mc-fade {
        from {
          opacity: 0;
          transform: scale(0.85);
        }
        to {
          opacity: 1;
          transform: scale(1);
        }
      }
      :root {
        --spectrum-track: rgba(0, 0, 0, 0.06);
        --spectrum-series-1: #3b82f6;
        --spectrum-series-2: #06b6d4;
        --spectrum-series-3: #10b981;
        --spectrum-series-4: #f43f5e;
        --spectrum-series-5: #f59e0b;
        --spectrum-series-6: #8b5cf6;
      }
      [data-theme="dark"] {
        --spectrum-track: rgba(255, 255, 255, 0.08);
        --spectrum-series-1: #60a5fa;
        --spectrum-series-2: #22d3ee;
        --spectrum-series-3: #34d399;
        --spectrum-series-4: #fb7185;
        --spectrum-series-5: #fbbf24;
        --spectrum-series-6: #a78bfa;
      }
    `}</style>
  );
}

export function useElementWidth<T extends HTMLElement>(): [
  React.RefObject<T | null>,
  number,
] {
  const ref = React.useRef<T | null>(null);
  const [width, setWidth] = React.useState(0);

  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) setWidth(Math.floor(w));
      }
    });
    ro.observe(el);
    setWidth(Math.floor(el.getBoundingClientRect().width));
    return () => ro.disconnect();
  }, []);

  return [ref, width];
}

export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = React.useState(false);

  React.useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  return reduced;
}

export function Stat({
  ready = true,
  children,
}: {
  ready?: boolean;
  children: React.ReactNode;
}) {
  if (!ready) {
    return (
      <span className="inline-block h-3 w-16 animate-pulse rounded bg-neutral-200 dark:bg-neutral-800" />
    );
  }
  return <>{children}</>;
}

export function ChartState({
  status = "ready",
  height,
  variant: _variant = "grid",
  empty = {
    title: "No activity yet",
    description: "The grid fills in as daily events are recorded.",
  },
  onRetry,
  children,
}: {
  status?: ChartStatus;
  height?: number;
  variant?: string;
  empty?: { title: string; description: string };
  onRetry?: () => void;
  children: React.ReactNode;
}) {
  if (status === "loading") {
    return (
      <div
        style={{ height: height ? `${height}px` : "160px" }}
        className="flex w-full items-center justify-center rounded-lg border border-dashed border-neutral-200 dark:border-neutral-800"
      >
        <div className="flex items-center gap-2 text-xs font-mono text-neutral-400">
          <span className="size-2 animate-ping rounded-full bg-neutral-400" />
          Loading chart...
        </div>
      </div>
    );
  }
  if (status === "error") {
    return (
      <div
        style={{ height: height ? `${height}px` : "160px" }}
        className="flex w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-rose-300 dark:border-rose-900/50 p-4 text-center"
      >
        <p className="text-xs font-mono font-medium text-rose-500">
          Failed to load chart data
        </p>
        {onRetry && (
          <button
            onClick={onRetry}
            className="text-[11px] font-mono text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-200 underline"
          >
            Retry
          </button>
        )}
      </div>
    );
  }
  if (status === "empty") {
    return (
      <div
        style={{ height: height ? `${height}px` : "160px" }}
        className="flex w-full flex-col items-center justify-center gap-1 rounded-lg border border-dashed border-neutral-200 dark:border-neutral-800 p-4 text-center"
      >
        <p className="text-xs font-mono font-medium text-neutral-700 dark:text-neutral-300">
          {empty.title}
        </p>
        <p className="text-[11px] font-mono text-neutral-400">
          {empty.description}
        </p>
      </div>
    );
  }
  return <>{children}</>;
}

