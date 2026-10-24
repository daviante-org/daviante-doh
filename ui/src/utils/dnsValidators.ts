/**
 * Strict RFC 1035 / RFC 1123 domain validation.
 * Allows underscore prefixes for SRV/TLSA/TXT/HTTPS/SVCB/URI/CNAME/DKIM/DMARC records.
 */
export function isValidDnsDomain(domain: string, allowWildcardPrefix = false): boolean {
  const normalized = domain.trim().replace(/\.$/, '').toLowerCase();
  if (normalized.length === 0 || normalized.length > 253) {
    return false;
  }
  const labels = normalized.split('.');
  for (let idx = 0; idx < labels.length; idx += 1) {
    const label = labels[idx];
    if (label === undefined || label.length === 0 || label.length > 63) {
      return false;
    }
    if (label === '*') {
      if (!allowWildcardPrefix || idx !== 0 || labels.length < 2) {
        return false;
      }
      continue;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
    for (let i = 0; i < label.length; i += 1) {
      const ch = label.charCodeAt(i);
      const isAlphaNum = (ch >= 97 && ch <= 122) || (ch >= 48 && ch <= 57);
      const isAllowedSpecial = ch === 45 || ch === 95; // '-' or '_'
      if (!isAlphaNum && !isAllowedSpecial) {
        return false;
      }
    }
  }
  return true;
}

/**
 * Resolves a user-entered owner name (`@`, `*`, relative subdomain `api`, or full FQDN)
 * against an optional zone name (e.g. `internal.corp`).
 */
export function resolveOwnerInZone(inputOwner: string, zoneName?: string | null): string {
  const raw = inputOwner.trim().replace(/\.$/, '').toLowerCase();
  const cleanZone = zoneName?.trim().replace(/\.$/, '').toLowerCase() ?? '';
  if (!cleanZone) {
    return raw;
  }
  if (raw === '@' || raw === '' || raw === cleanZone) {
    return cleanZone;
  }
  if (raw === '*') {
    return `*.${cleanZone}`;
  }
  if (raw.endsWith(`.${cleanZone}`)) {
    return raw;
  }
  return `${raw}.${cleanZone}`;
}

/**
 * Validates an owner input (`@`, `*`, relative label, FQDN, or raw IP for PTR)
 * when optionally scoped to a DNS Zone.
 */
export function isValidDnsOwnerInZone(
  inputOwner: string,
  zoneName?: string | null,
  recordType?: string
): boolean {
  const raw = inputOwner.trim();
  if (raw.length === 0) {
    return false;
  }
  // PTR records allow raw IPv4 or IPv6 addresses, which backend canonicalizes to .in-addr.arpa / .ip6.arpa
  if (recordType === 'PTR' && (isValidIpv4(raw) || isValidIpv6(raw))) {
    return true;
  }
  const resolved = resolveOwnerInZone(raw, zoneName);
  return isValidDnsDomain(resolved, true);
}

export function isValidTargetOrRootDot(target: string): boolean {
  const trimmed = target.trim();
  if (trimmed === '.') {
    return true;
  }
  return isValidDnsDomain(trimmed, false);
}

/**
 * Strict IPv4 validation (four decimal octets 0..255 without leading zeros).
 */
export function isValidIpv4(ip: string): boolean {
  const trimmed = ip.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 4) {
    return false;
  }
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) {
      return false;
    }
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) {
      return false;
    }
  }
  return true;
}

/**
 * Strict RFC 4291 IPv6 address validation (supports '::' compression and IPv4-mapped suffix).
 */
export function isValidIpv6(ip: string): boolean {
  const trimmed = ip.trim();
  if (trimmed.length < 2 || trimmed.length > 45 || trimmed.includes('%')) {
    return false;
  }
  try {
    const parsed = new URL(`http://[${trimmed}]/`);
    return parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']');
  } catch {
    return false;
  }
}

export function isValidHex(input: string, exactBytes?: number): boolean {
  const normalized = input.replace(/\s+/g, '');
  if (normalized.length === 0 || normalized.length % 2 !== 0) {
    return false;
  }
  if (exactBytes !== undefined && normalized.length !== exactBytes * 2) {
    return false;
  }
  return /^[0-9a-fA-F]+$/.test(normalized);
}

export function isValidBase64(input: string): boolean {
  const normalized = input.replace(/\s+/g, '');
  if (normalized.length === 0 || normalized.length % 4 !== 0) {
    return false;
  }
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized);
}

export function isValidLocCoordinates(coords: string): boolean {
  const re =
    /^\d{1,2}(?:\s+\d{1,2}(?:\s+\d{1,2}(?:\.\d{1,3})?)?)?\s+[NSns]\s+\d{1,3}(?:\s+\d{1,2}(?:\s+\d{1,2}(?:\.\d{1,3})?)?)?\s+[EWew]\s+-?\d+(?:\.\d{1,2})?m?(?:\s+\d+(?:\.\d{1,2})?m?){0,3}$/;
  return re.test(coords.trim());
}

const KNOWN_SVC_PARAM_KEYS = new Set([
  'mandatory',
  'alpn',
  'no-default-alpn',
  'port',
  'ipv4hint',
  'ech',
  'ipv6hint',
  'dohpath',
  'ohttp'
]);

export function isValidSvcParams(params: string): string | null {
  const trimmed = params.trim();
  if (trimmed.length === 0) {
    return null;
  }
  if (trimmed.length > 1024) {
    return 'SvcParams must not exceed 1024 characters.';
  }
  const tokens = trimmed.split(/\s+/);
  for (const token of tokens) {
    const eqIndex = token.indexOf('=');
    const key = (eqIndex >= 0 ? token.slice(0, eqIndex) : token).toLowerCase();
    const val = eqIndex >= 0 ? token.slice(eqIndex + 1).replace(/^"|"$/g, '') : '';
    const isKeyN = /^key\d+$/.test(key);
    if (!KNOWN_SVC_PARAM_KEYS.has(key) && !isKeyN) {
      return `Unknown RFC 9460 SvcParam key '${key}'. Use standard keys (alpn, port, ipv4hint, ipv6hint, ech, mandatory, no-default-alpn, dohpath) or keyNNNN.`;
    }
    if (key !== 'no-default-alpn' && eqIndex < 0) {
      return `SvcParam '${key}' requires a '=value' assignment.`;
    }
    if (key === 'port') {
      const p = Number(val);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        return 'SvcParam port must be between 1 and 65535.';
      }
    }
    if (key === 'ipv4hint') {
      for (const ip of val.split(',')) {
        if (!isValidIpv4(ip)) {
          return `Invalid IPv4 address '${ip}' in ipv4hint.`;
        }
      }
    }
    if (key === 'ipv6hint') {
      for (const ip of val.split(',')) {
        if (!isValidIpv6(ip)) {
          return `Invalid IPv6 address '${ip}' in ipv6hint.`;
        }
      }
    }
  }
  return null;
}
