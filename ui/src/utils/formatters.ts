export function formatHumanTtl(ttl: number): string {
  if (ttl === 60) return '1m (60s)';
  if (ttl === 120) return '2m (120s)';
  if (ttl === 300) return '5m (300s)';
  if (ttl === 900) return '15m (900s)';
  if (ttl === 1800) return '30m (1800s)';
  if (ttl === 3600) return '1h (3600s)';
  if (ttl === 43200) return '12h (43200s)';
  if (ttl === 86400) return '1d (86400s)';
  return `${String(ttl)}s`;
}

export function formatUpdatedEpoch(epoch: number): string {
  if (!epoch || epoch <= 0) {
    return '—';
  }
  try {
    return new Date(epoch * 1000).toLocaleString();
  } catch {
    return String(epoch);
  }
}

export function formatEpochSeconds(epoch: number): string {
  try {
    return new Date(epoch * 1000).toLocaleTimeString();
  } catch {
    return String(epoch);
  }
}

export function parseIntClamped(raw: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, parsed));
}
