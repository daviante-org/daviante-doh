/**
 * URL Sanitizer (AGENTS.md Rule 4.1)
 * Allows only safe relative paths ('/...') or http:/https: URLs without embedded credentials.
 * Rejects javascript:, data:, vbscript:, mixed-case, control characters, and protocol-relative URLs.
 */
export function isSafeHrefUrl(rawUrl: string): boolean {
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) {
    return false;
  }
  // Reject control characters or embedded whitespace that browsers normalize in schemes
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) {
      return false;
    }
  }
  // Safe single-slash relative path
  if (trimmed.startsWith('/') && !trimmed.startsWith('//') && !trimmed.startsWith('/\\')) {
    return true;
  }
  try {
    const parsed = new URL(trimmed);
    const protocol = parsed.protocol.toLowerCase();
    if (protocol !== 'https:' && protocol !== 'http:') {
      return false;
    }
    if (parsed.username !== '' || parsed.password !== '') {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}
