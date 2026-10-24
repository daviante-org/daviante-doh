export const DNS_RECORD_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'ANAME',
  'MX',
  'TXT',
  'SPF',
  'SRV',
  'HTTPS',
  'SVCB',
  'PTR',
  'NS',
  'SOA',
  'CAA',
  'TLSA',
  'SMIMEA',
  'SSHFP',
  'NAPTR',
  'URI',
  'LOC',
  'HINFO',
  'RP',
  'DNAME',
  'DS',
  'DNSKEY',
  'OPENPGPKEY',
  'CERT',
  'CSYNC',
  'RAW'
] as const;

export type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];

export interface RecordTypeGroup {
  readonly label: string;
  readonly types: readonly { readonly value: DnsRecordType; readonly label: string }[];
}

export const RECORD_TYPE_GROUPS: readonly RecordTypeGroup[] = [
  {
    label: 'Address & Aliasing',
    types: [
      { value: 'A', label: 'A — IPv4 Address (RFC 1035)' },
      { value: 'AAAA', label: 'AAAA — IPv6 Address (RFC 3596)' },
      { value: 'CNAME', label: 'CNAME — Canonical Name Alias (RFC 1035)' },
      { value: 'ANAME', label: 'ANAME — Zone Apex Alias (Draft)' },
      { value: 'DNAME', label: 'DNAME — Subtree Delegation Alias (RFC 6672)' },
      { value: 'PTR', label: 'PTR — Reverse DNS Pointer (RFC 1035)' }
    ]
  },
  {
    label: 'Mail, Text & Policy',
    types: [
      { value: 'MX', label: 'MX — Mail Exchange (RFC 1035)' },
      { value: 'TXT', label: 'TXT — Arbitrary Text / Verification (RFC 1035)' },
      { value: 'SPF', label: 'SPF — Sender Policy Framework (RFC 7208)' }
    ]
  },
  {
    label: 'Service Discovery & Routing',
    types: [
      { value: 'SRV', label: 'SRV — Service Locator (RFC 2782)' },
      { value: 'HTTPS', label: 'HTTPS — HTTPS Service Binding (RFC 9460)' },
      { value: 'SVCB', label: 'SVCB — General Service Binding (RFC 9460)' },
      { value: 'NAPTR', label: 'NAPTR — Naming Authority Pointer (RFC 3403)' },
      { value: 'URI', label: 'URI — Uniform Resource Identifier (RFC 7553)' }
    ]
  },
  {
    label: 'Security, TLS & DNSSEC',
    types: [
      { value: 'CAA', label: 'CAA — Certification Authority Authorization (RFC 8659)' },
      { value: 'TLSA', label: 'TLSA — DANE TLS Certificate Association (RFC 6698)' },
      { value: 'SMIMEA', label: 'SMIMEA — S/MIME Certificate Association (RFC 8162)' },
      { value: 'SSHFP', label: 'SSHFP — SSH Public Key Fingerprint (RFC 4255)' },
      { value: 'DS', label: 'DS — Delegation Signer (RFC 4034)' },
      { value: 'DNSKEY', label: 'DNSKEY — DNSSEC Public Key (RFC 4034)' },
      { value: 'OPENPGPKEY', label: 'OPENPGPKEY — OpenPGP Public Key (RFC 7929)' },
      { value: 'CERT', label: 'CERT — Cryptographic Certificate (RFC 4398)' },
      { value: 'CSYNC', label: 'CSYNC — Child-to-Parent Synchronization (RFC 7477)' }
    ]
  },
  {
    label: 'Zone Authority & Infrastructure',
    types: [
      { value: 'NS', label: 'NS — Authoritative Name Server (RFC 1035)' },
      { value: 'SOA', label: 'SOA — Start of Authority (RFC 1035)' },
      { value: 'LOC', label: 'LOC — Geographical Location (RFC 1876)' },
      { value: 'HINFO', label: 'HINFO — Host Information (RFC 8482)' },
      { value: 'RP', label: 'RP — Responsible Person (RFC 1183)' },
      { value: 'RAW', label: 'RAW — Arbitrary RFC 3597 Wire Format' }
    ]
  }
];

export const TTL_PRESETS = [
  { label: '1 min (60s)', value: 60 },
  { label: '2 min (120s)', value: 120 },
  { label: '5 min (300s - Auto)', value: 300 },
  { label: '15 min (900s)', value: 900 },
  { label: '30 min (1800s)', value: 1800 },
  { label: '1 hour (3600s)', value: 3600 },
  { label: '12 hours (43200s)', value: 43200 },
  { label: '1 day (86400s)', value: 86400 }
] as const;

export const PER_PAGE_OPTIONS = [
  { title: '10 per page', value: 10 },
  { title: '20 per page', value: 20 },
  { title: '50 per page', value: 50 },
  { title: '100 per page', value: 100 }
] as const;

export type RecordCategoryFilter = 'ALL' | 'ADDRESS' | 'MAIL_TEXT' | 'SERVICE' | 'SECURITY' | 'INFRA';
