export const DAVIANTE_ORG_URL = 'https://github.com/orgs/daviante-org';
export const DAVIANTE_REPO_URL = 'https://github.com/daviante-org/daviante-doh';
export const APACHE_LICENSE_URL = 'https://www.apache.org/licenses/LICENSE-2.0';

export interface RfcStandardEntry {
  readonly rfc: string;
  readonly title: string;
  readonly scope: string;
  readonly status: 'Enforced' | 'Supported';
}

export const RFC_STANDARDS_MATRIX: readonly RfcStandardEntry[] = [
  {
    rfc: 'RFC 8484',
    title: 'DNS Queries over HTTPS (DoH)',
    scope: 'GET (?dns= base64url) & POST (application/dns-message) wire transport over HTTP/2 & HTTP/3',
    status: 'Enforced'
  },
  {
    rfc: 'RFC 1034 / 1035',
    title: 'Domain Names — Concepts, Facilities & Implementation',
    scope: 'Authoritative & Split-Horizon zone trees, SOA serial management, and 63-octet label validation',
    status: 'Enforced'
  },
  {
    rfc: 'RFC 2181 §10.1',
    title: 'Clarifications to the DNS Specification (CNAME Exclusivity)',
    scope: 'Strict prevention of CNAME coexistence with other RRsets at the same owner name and cycle detection',
    status: 'Enforced'
  },
  {
    rfc: 'RFC 9460',
    title: 'Service Binding and Parameter Specification via the DNS (SVCB and HTTPS)',
    scope: 'AliasMode (Priority 0) and ServiceMode (Priority > 0) with SvcParams validation (alpn, ipv4hint, ech)',
    status: 'Supported'
  },
  {
    rfc: 'RFC 6698 / 8162 / 8659',
    title: 'DANE TLSA, S/MIMEA & Certification Authority Authorization (CAA)',
    scope: 'Cryptographic certificate pinning, SHA-256/SHA-512 hex digest verification, and CA issuance controls',
    status: 'Supported'
  },
  {
    rfc: 'RFC 4034 / 4255 / 7477',
    title: 'DNSSEC Resource Records (DS, DNSKEY, CSYNC) & SSHFP',
    scope: 'Delegation Signer digests, public key base64 validation, and SSH host key fingerprints',
    status: 'Supported'
  },
  {
    rfc: 'RFC 9457',
    title: 'Problem Details for HTTP APIs',
    scope: 'Standardized machine-readable error codes mapped to static user-safe messages with zero stack-trace leakage',
    status: 'Enforced'
  },
  {
    rfc: 'OWASP ASVS v4.0 L2',
    title: 'Application Security Verification Standard Level 2',
    scope: '__Host- HttpOnly session cookies, Argon2id (m=19MiB, t=2, p=1), CSRF double-check, and RBAC enforcement',
    status: 'Enforced'
  }
];
