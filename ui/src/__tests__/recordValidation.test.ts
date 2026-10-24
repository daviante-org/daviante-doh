import { describe, expect, it } from 'vitest';
import { DNS_RECORD_TYPES } from '../constants';
import {
  defaultRecordDataForType,
  formatLiveBindPreview,
   type LocalDnsRecordView,
  validateRecordAgainstExisting,
  validateRecordData
} from '../features/dns-records';
import { mapErrorCodeToStaticMessage } from '../services';
import { RecordIdSchema } from '../types';
import {
  isSafeHrefUrl,
  isValidDnsDomain,
  isValidDnsOwnerInZone,
  isValidIpv4,
  isValidIpv6,
  isValidLocCoordinates,
  resolveOwnerInZone
} from '../utils';

describe('URL Sanitizer (Rule 4.1 & Section 7)', () => {
  it('accepts safe relative paths and http/https URLs without credentials', () => {
    expect(isSafeHrefUrl('/api/v1/auth/oidc/login')).toBe(true);
    expect(isSafeHrefUrl('https://sso.internal.corp/realms/main')).toBe(true);
    expect(isSafeHrefUrl('http://localhost:8080/callback')).toBe(true);
  });

  it('rejects javascript:, data:, vbscript:, mixed-case, whitespace/control chars, protocol-relative, and credentialed URLs', () => {
    expect(isSafeHrefUrl('javascript:alert(1)')).toBe(false);
    expect(isSafeHrefUrl('JaVaScRiPt:alert(1)')).toBe(false);
    expect(isSafeHrefUrl('   javascript:alert(1)   ')).toBe(false);
    expect(isSafeHrefUrl('java\x00script:alert(1)')).toBe(false);
    expect(isSafeHrefUrl('java\tscript:alert(1)')).toBe(false);
    expect(isSafeHrefUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
    expect(isSafeHrefUrl('DATA:text/plain;base64,SGVsbG8=')).toBe(false);
    expect(isSafeHrefUrl('vbscript:msgbox(1)')).toBe(false);
    expect(isSafeHrefUrl('//evil.example.com/phish')).toBe(false);
    expect(isSafeHrefUrl('https://user:pass@evil.example.com/')).toBe(false);
    expect(isSafeHrefUrl('')).toBe(false);
  });
});

describe('All-29 DNS Record Type Validation & Live BIND Preview', () => {
  it('validates default templates and formats BIND zone preview for all 29 record types', () => {
    expect(DNS_RECORD_TYPES.length).toBe(29);
    for (const rrType of DNS_RECORD_TYPES) {
      const sample = defaultRecordDataForType(rrType);
      expect(sample.type).toBe(rrType);
      expect(validateRecordData(sample)).toBeNull();
      const bindLine = formatLiveBindPreview('svc.internal.corp', 300, sample);
      expect(bindLine).toContain('svc.internal.corp. 300 IN');
    }
  });

  it('rejects malformed IPv4, IPv6, domain names, SvcParams, TLSA/SSHFP/DS digests, and meta RR types', () => {
    expect(isValidIpv4('192.168.1.256')).toBe(false);
    expect(isValidIpv4('192.168.01.1')).toBe(false);
    expect(isValidIpv6('2001:db8::1::2')).toBe(false);
    expect(isValidDnsDomain('-bad.example.com', false)).toBe(false);
    expect(isValidDnsDomain('*.sub.example.com', false)).toBe(false);
    expect(isValidDnsDomain('*.sub.example.com', true)).toBe(true);

    expect(
      validateRecordData({
        type: 'HTTPS',
        priority: 0,
        target: 'cdn.example.com',
        svc_params: 'alpn="h2"'
      })
    ).toContain('AliasMode');

    expect(
      validateRecordData({
        type: 'TLSA',
        usage: 3,
        selector: 1,
        matching_type: 1,
        cert_data: 'deadbeef'
      })
    ).toContain('64-character hexadecimal');

    expect(
      validateRecordData({
        type: 'RAW',
        rr_type: 255,
        rdata_hex: 'deadbeef'
      })
    ).toContain('Meta/QTYPE');
  });

  it('enforces RFC 2181 §10.1 CNAME exclusivity and CNAME loop detection', () => {
    const existing: LocalDnsRecordView[] = [
      {
        id: RecordIdSchema.parse('rec-1'),
        domain: 'app.internal.corp',
        ttl: 300,
        enabled: true,
        comment: '',
        updated_at: '100',
        updated_at_epoch: 100,
        record: { type: 'A', ip: '10.0.0.10', auto_ptr: false },
        rr_type_code: 1,
        bind_preview: 'app.internal.corp. 300 IN A 10.0.0.10'
      },
      {
        id: RecordIdSchema.parse('rec-2'),
        domain: 'hop1.internal.corp',
        ttl: 300,
        enabled: true,
        comment: '',
        updated_at: '100',
        updated_at_epoch: 100,
        record: { type: 'CNAME', target: 'hop2.internal.corp' },
        rr_type_code: 5,
        bind_preview: 'hop1.internal.corp. 300 IN CNAME hop2.internal.corp.'
      }
    ];

    // Adding a CNAME where an A record already exists
    const cnameConflict = validateRecordAgainstExisting(
      'app.internal.corp',
      { type: 'CNAME', target: 'other.internal.corp' },
      existing
    );
    expect(cnameConflict).toContain('RFC 2181');

    // Adding an MX where a CNAME already exists
    const reverseConflict = validateRecordAgainstExisting(
      'hop1.internal.corp',
      { type: 'MX', priority: 10, target: 'mail.internal.corp' },
      existing
    );
    expect(reverseConflict).toContain('RFC 2181');

    // Creating a CNAME cycle: hop2 -> hop1 (when hop1 -> hop2 exists)
    const loopErr = validateRecordAgainstExisting(
      'hop2.internal.corp',
      { type: 'CNAME', target: 'hop1.internal.corp' },
      existing
    );
    expect(loopErr).toContain('CNAME Loop Detected');
  });

  it('resolves @, *, relative subdomains, and FQDNs inside a DNS Zone and validates RFC 1876 LOC precision', () => {
    expect(resolveOwnerInZone('@', 'internal.corp')).toBe('internal.corp');
    expect(resolveOwnerInZone('*', 'internal.corp')).toBe('*.internal.corp');
    expect(resolveOwnerInZone('api', 'internal.corp')).toBe('api.internal.corp');
    expect(resolveOwnerInZone('*.dev', 'internal.corp')).toBe('*.dev.internal.corp');
    expect(resolveOwnerInZone('db.internal.corp.', 'internal.corp')).toBe('db.internal.corp');

    expect(isValidDnsOwnerInZone('@', 'internal.corp', 'A')).toBe(true);
    expect(isValidDnsOwnerInZone('api.v2', 'internal.corp', 'AAAA')).toBe(true);
    expect(isValidDnsOwnerInZone('10.20.0.15', null, 'PTR')).toBe(true);
    expect(isValidDnsOwnerInZone('-invalid', 'internal.corp', 'A')).toBe(false);

    // RFC 1876 LOC with optional size, horiz_pre, vert_pre
    expect(isValidLocCoordinates('37 46 29.744 N 122 25 9.816 W 15.00m 1m 10000m 10m')).toBe(true);
    expect(isValidLocCoordinates('52 14 05.000 N 00 08 50.000 E 10m')).toBe(true);
    // Reject >4 tokens after E/W
    expect(
      isValidLocCoordinates('37 46 29.744 N 122 25 9.816 W 15.00m 1m 10000m 10m extra')
    ).toBe(false);

    expect(mapErrorCodeToStaticMessage('ZONE_NOT_FOUND')).toContain('DNS zone');
    expect(mapErrorCodeToStaticMessage('INVALID_CREDENTIALS')).toBe(
      'Invalid username or password.'
    );
  });
});
