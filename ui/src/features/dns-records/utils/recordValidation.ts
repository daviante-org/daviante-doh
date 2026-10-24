import { z } from 'zod';
import type { DnsRecordType } from '../../../constants';
import type { RecordId } from '../../../types';
import {
  assertNever,
  isSafeHrefUrl,
  isValidBase64,
  isValidDnsDomain,
  isValidHex,
  isValidIpv4,
  isValidIpv6,
  isValidLocCoordinates,
  isValidSvcParams,
  isValidTargetOrRootDot
} from '../../../utils';
import {
  type LocalDnsRecordView,
  type LocalRecordData,
  LocalRecordDataSchema
} from '../types/dnsRecords.types';

/**
 * Exhaustive client-side RDATA validation for all 29 DNS record types.
 * Returns null if valid, or a descriptive validation error message.
 */
export function validateRecordData(record: LocalRecordData): string | null {
  switch (record.type) {
    case 'A':
      return isValidIpv4(record.ip)
        ? null
        : 'Enter a valid IPv4 address in dotted-quad notation (e.g., 192.0.2.10).';
    case 'AAAA':
      return isValidIpv6(record.ip)
        ? null
        : 'Enter a valid RFC 4291 IPv6 address (e.g., 2001:db8::10).';
    case 'CNAME':
    case 'ANAME':
    case 'DNAME':
    case 'NS':
    case 'PTR':
      return isValidDnsDomain(record.target, false)
        ? null
        : `Enter a valid target FQDN for ${record.type} (e.g., target.example.com).`;
    case 'MX':
      if (record.priority < 0 || record.priority > 65535) {
        return 'MX priority must be between 0 and 65535.';
      }
      return isValidTargetOrRootDot(record.target)
        ? null
        : 'Enter a valid mail server FQDN or "." for Null MX (RFC 7505).';
    case 'TXT': {
      const trimmed = record.content.trim();
      if (trimmed.length === 0) {
        return 'TXT content must not be empty.';
      }
      if (trimmed.length > 4096) {
        return 'TXT content must not exceed 4096 characters.';
      }
      return null;
    }
    case 'SPF': {
      const trimmed = record.content.trim();
      if (!trimmed.toLowerCase().startsWith('v=spf1')) {
        return 'SPF record content must start with "v=spf1" (RFC 7208).';
      }
      if (trimmed.length > 2048) {
        return 'SPF content must not exceed 2048 characters.';
      }
      return null;
    }
    case 'SRV':
      if (record.priority < 0 || record.priority > 65535) {
        return 'SRV priority must be between 0 and 65535.';
      }
      if (record.weight < 0 || record.weight > 65535) {
        return 'SRV weight must be between 0 and 65535.';
      }
      if (record.port < 1 || record.port > 65535) {
        return 'SRV port must be between 1 and 65535.';
      }
      return isValidTargetOrRootDot(record.target)
        ? null
        : 'Enter a valid SRV target host or "." if the service is decidedly not available.';
    case 'HTTPS':
    case 'SVCB': {
      if (record.priority < 0 || record.priority > 65535) {
        return `${record.type} priority must be between 0 and 65535.`;
      }
      if (!isValidTargetOrRootDot(record.target)) {
        return `Enter a valid ${record.type} target name or "." for the owner name.`;
      }
      if (record.priority === 0 && record.svc_params.trim().length > 0) {
        return `${record.type} AliasMode (priority 0) must not include SvcParams (RFC 9460 §2.4.2).`;
      }
      return isValidSvcParams(record.svc_params);
    }
    case 'SOA':
      if (!isValidDnsDomain(record.mname, false)) {
        return 'SOA Primary Nameserver (MNAME) must be a valid FQDN.';
      }
      if (!isValidDnsDomain(record.rname, false)) {
        return 'SOA Responsible Mailbox (RNAME) must be a valid domain-formatted mailbox (e.g., hostmaster.example.com).';
      }
      if (record.refresh <= 0 || record.retry <= 0 || record.expire <= 0) {
        return 'SOA refresh, retry, and expire timers must be positive integers.';
      }
      return null;
    case 'CAA': {
      if (record.flags !== 0 && record.flags !== 128) {
        return 'CAA flags should be 0 (non-critical) or 128 (issuer critical).';
      }
      const tag = record.tag.trim().toLowerCase();
      if (tag !== 'issue' && tag !== 'issuewild' && tag !== 'iodef' && tag !== 'contactemail') {
        return 'CAA tag must be one of: issue, issuewild, iodef, contactemail.';
      }
      if (record.value.trim().length === 0 || record.value.trim().length > 512) {
        return 'CAA value must be between 1 and 512 characters.';
      }
      return null;
    }
    case 'TLSA':
    case 'SMIMEA': {
      if (record.usage < 0 || record.usage > 3) {
        return `${record.type} certificate usage must be 0, 1, 2, or 3.`;
      }
      if (record.selector < 0 || record.selector > 1) {
        return `${record.type} selector must be 0 (Full Cert) or 1 (SubjectPublicKeyInfo).`;
      }
      if (record.matching_type < 0 || record.matching_type > 2) {
        return `${record.type} matching type must be 0 (Exact), 1 (SHA-256), or 2 (SHA-512).`;
      }
      const exactBytes =
        record.matching_type === 1 ? 32 : record.matching_type === 2 ? 64 : undefined;
      if (!isValidHex(record.cert_data, exactBytes)) {
        if (exactBytes === 32) {
          return `${record.type} with SHA-256 (matching type 1) requires a 64-character hexadecimal digest (32 bytes).`;
        }
        if (exactBytes === 64) {
          return `${record.type} with SHA-512 (matching type 2) requires a 128-character hexadecimal digest (64 bytes).`;
        }
        return `${record.type} certificate association data must be valid even-length hexadecimal.`;
      }
      return null;
    }
    case 'SSHFP': {
      if (record.algorithm < 1 || record.algorithm > 6) {
        return 'SSHFP algorithm must be between 1 (RSA) and 6 (Ed448).';
      }
      if (record.fp_type !== 1 && record.fp_type !== 2) {
        return 'SSHFP fingerprint type must be 1 (SHA-1, 20 bytes) or 2 (SHA-256, 32 bytes).';
      }
      const expectedBytes = record.fp_type === 1 ? 20 : 32;
      if (!isValidHex(record.fingerprint, expectedBytes)) {
        return `SSHFP type ${String(record.fp_type)} requires a ${String(expectedBytes * 2)}-character hexadecimal fingerprint (${String(expectedBytes)} bytes).`;
      }
      return null;
    }
    case 'NAPTR': {
      const flags = record.flags.trim().toUpperCase();
      if (!/^[SAUP]?$/.test(flags)) {
        return 'NAPTR flags must be empty or one of "S", "A", "U", or "P".';
      }
      if (record.service.trim().length > 128) {
        return 'NAPTR service field must not exceed 128 characters.';
      }
      if (!isValidTargetOrRootDot(record.replacement)) {
        return 'NAPTR replacement must be "." or a valid FQDN.';
      }
      return null;
    }
    case 'URI': {
      const target = record.target.trim();
      if (target.length === 0 || target.length > 1024) {
        return 'URI target must be between 1 and 1024 characters.';
      }
      if (!isSafeHrefUrl(target) && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s"]+$/i.test(target)) {
        return 'URI target must be a valid RFC 3986 URI (e.g., https://svc.example.com/api).';
      }
      return null;
    }
    case 'LOC':
      return isValidLocCoordinates(record.coordinates)
        ? null
        : 'LOC coordinates must follow RFC 1876 format (e.g., "37 46 29.744 N 122 25 9.816 W 15.00m").';
    case 'HINFO':
      if (record.cpu.trim().length === 0 || record.cpu.trim().length > 128) {
        return 'HINFO CPU identifier must be between 1 and 128 characters.';
      }
      if (record.os.trim().length === 0 || record.os.trim().length > 128) {
        return 'HINFO OS identifier must be between 1 and 128 characters.';
      }
      return null;
    case 'RP':
      if (!isValidDnsDomain(record.mbox, false)) {
        return 'RP mailbox (MBOX) must be a valid domain-formatted mailbox (e.g., ops.example.com).';
      }
      if (!isValidTargetOrRootDot(record.txt)) {
        return 'RP TXT pointer must be "." or a valid FQDN.';
      }
      return null;
    case 'DS': {
      const expectedBytes =
        record.digest_type === 1
          ? 20
          : record.digest_type === 2
            ? 32
            : record.digest_type === 4
              ? 48
              : undefined;
      if (!isValidHex(record.digest, expectedBytes)) {
        return expectedBytes !== undefined
          ? `DS digest type ${String(record.digest_type)} requires a ${String(expectedBytes * 2)}-character hexadecimal digest (${String(expectedBytes)} bytes).`
          : 'DS digest must be valid even-length hexadecimal.';
      }
      return null;
    }
    case 'DNSKEY':
      if (record.flags !== 256 && record.flags !== 257 && record.flags !== 0) {
        return 'DNSKEY flags are typically 256 (ZSK) or 257 (KSK / SEP).';
      }
      if (record.protocol !== 3) {
        return 'DNSKEY protocol field must be 3 per RFC 4034 §2.1.2.';
      }
      if (!isValidBase64(record.public_key)) {
        return 'DNSKEY public key must be valid Base64.';
      }
      return null;
    case 'OPENPGPKEY':
      return isValidBase64(record.public_key)
        ? null
        : 'OPENPGPKEY public key payload must be valid Base64.';
    case 'CERT':
      return isValidBase64(record.cert_data)
        ? null
        : 'CERT certificate payload must be valid Base64.';
    case 'CSYNC': {
      const tokens = record.types
        .trim()
        .split(/\s+/)
        .filter((t) => t.length > 0);
      if (tokens.length === 0) {
        return 'CSYNC type bitmap must list at least one RR type (e.g., "A AAAA NS").';
      }
      return null;
    }
    case 'RAW': {
      const forbiddenMeta = new Set([0, 41, 249, 250, 251, 252, 255]);
      if (forbiddenMeta.has(record.rr_type)) {
        return `RR type ${String(record.rr_type)} is a DNS Meta/QTYPE (OPT, TKEY, TSIG, IXFR, AXFR, ANY) and cannot be stored as authoritative zone data.`;
      }
      if (!isValidHex(record.rdata_hex)) {
        return 'RAW RDATA must be non-empty, even-length hexadecimal.';
      }
      return null;
    }
    default:
      return assertNever(record);
  }
}

/**
 * Client-side RFC 2181 §10.1 CNAME exclusivity & CNAME cycle pre-validation
 * against currently loaded records.
 */
export function validateRecordAgainstExisting(
  domain: string,
  record: LocalRecordData,
  existingRecords: readonly LocalDnsRecordView[],
  editingRecordId?: RecordId
): string | null {
  const normalizedDomain = domain.trim().replace(/\.$/, '').toLowerCase();

  for (const existing of existingRecords) {
    if (editingRecordId !== undefined && existing.id === editingRecordId) {
      continue;
    }
    if (!existing.enabled) {
      continue;
    }
    const existingDomain = existing.domain.trim().replace(/\.$/, '').toLowerCase();
    if (existingDomain === normalizedDomain) {
      if (record.type === 'CNAME' || existing.record.type === 'CNAME') {
        return `RFC 2181 §10.1 CNAME Exclusivity Conflict: '${normalizedDomain}' already has a ${existing.record.type} record. A CNAME record cannot coexist with any other record at the same owner name.`;
      }
    }
  }

  if (record.type === 'CNAME' || record.type === 'ANAME') {
    const startTarget = record.target.trim().replace(/\.$/, '').toLowerCase();
    if (startTarget === normalizedDomain) {
      return `CNAME Loop Detected: '${normalizedDomain}' cannot alias to itself.`;
    }
    const visited = new Set<string>([normalizedDomain]);
    let current = startTarget;
    for (let hop = 0; hop < 16; hop += 1) {
      if (visited.has(current)) {
        return `CNAME Loop Detected: alias chain from '${normalizedDomain}' forms a cycle involving '${current}'.`;
      }
      visited.add(current);
      const nextHop = existingRecords.find(
        (r) =>
          r.enabled &&
          r.id !== editingRecordId &&
          r.domain.trim().replace(/\.$/, '').toLowerCase() === current &&
          (r.record.type === 'CNAME' || r.record.type === 'ANAME')
      );
      if (!nextHop) {
        break;
      }
      if (nextHop.record.type === 'CNAME' || nextHop.record.type === 'ANAME') {
        current = nextHop.record.target.trim().replace(/\.$/, '').toLowerCase();
      }
    }
  }

  return null;
}

export const UpsertRecordFormSchema = z
  .object({
    domain: z
      .string()
      .trim()
      .min(1, 'Owner / Domain is required.')
      .max(253, 'Domain must not exceed 253 characters.'),
    ttl: z
      .number()
      .int('TTL must be a whole number of seconds.')
      .min(1, 'Minimum TTL is 1 second.')
      .max(604800, 'Maximum TTL is 604800 seconds (7 days).'),
    enabled: z.boolean(),
    comment: z.string().max(256, 'Comment must not exceed 256 characters.'),
    record: LocalRecordDataSchema
  })
  .superRefine((values, ctx) => {
    const domainTrimmed = values.domain.trim();
    const isAutoReversePtr =
      values.record.type === 'PTR' &&
      (isValidIpv4(domainTrimmed) || isValidIpv6(domainTrimmed));

    const isShorthandApex = domainTrimmed === '@' || domainTrimmed === '*';
    if (!isAutoReversePtr && !isShorthandApex && !isValidDnsDomain(domainTrimmed, true)) {
      ctx.addIssue({
        code: 'custom',
        path: ['domain'],
        message:
          'Enter "@", "*", a relative subdomain (e.g., api), a valid FQDN, or an IP address when creating a PTR record.'
      });
    }

    const rdataErr = validateRecordData(values.record);
    if (rdataErr !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['record'],
        message: rdataErr
      });
    }
  });

export type UpsertRecordFormValues = z.infer<typeof UpsertRecordFormSchema>;

/**
 * Formats an instant RFC 1035 / BIND zone line preview on the client while typing.
 */
export function formatLiveBindPreview(
  domain: string,
  ttl: number,
  record: LocalRecordData
): string {
  const fqdn = `${(domain.trim().replace(/\.$/, '') || '@').toLowerCase()}.`;
  const safeTtl = String(Number.isFinite(ttl) && ttl > 0 ? ttl : 300);
  const dotTarget = (t: string): string => {
    const trimmed = t.trim();
    if (!trimmed || trimmed === '.') {
      return '.';
    }
    return `${trimmed.replace(/\.$/, '')}.`;
  };

  switch (record.type) {
    case 'A':
      return `${fqdn} ${safeTtl} IN A ${record.ip.trim() || '0.0.0.0'}`;
    case 'AAAA':
      return `${fqdn} ${safeTtl} IN AAAA ${record.ip.trim() || '::'}`;
    case 'CNAME':
      return `${fqdn} ${safeTtl} IN CNAME ${dotTarget(record.target)}`;
    case 'ANAME':
      return `${fqdn} ${safeTtl} IN ANAME ${dotTarget(record.target)}`;
    case 'MX':
      return `${fqdn} ${safeTtl} IN MX ${String(record.priority)} ${dotTarget(record.target)}`;
    case 'TXT':
      return `${fqdn} ${safeTtl} IN TXT "${record.content.replace(/"/g, '\\"')}"`;
    case 'SPF':
      return `${fqdn} ${safeTtl} IN SPF "${record.content.replace(/"/g, '\\"')}"`;
    case 'SRV':
      return `${fqdn} ${safeTtl} IN SRV ${String(record.priority)} ${String(record.weight)} ${String(record.port)} ${dotTarget(record.target)}`;
    case 'HTTPS': {
      const params = record.svc_params.trim();
      return params
        ? `${fqdn} ${safeTtl} IN HTTPS ${String(record.priority)} ${dotTarget(record.target)} ${params}`
        : `${fqdn} ${safeTtl} IN HTTPS ${String(record.priority)} ${dotTarget(record.target)}`;
    }
    case 'SVCB': {
      const params = record.svc_params.trim();
      return params
        ? `${fqdn} ${safeTtl} IN SVCB ${String(record.priority)} ${dotTarget(record.target)} ${params}`
        : `${fqdn} ${safeTtl} IN SVCB ${String(record.priority)} ${dotTarget(record.target)}`;
    }
    case 'PTR':
      return `${fqdn} ${safeTtl} IN PTR ${dotTarget(record.target)}`;
    case 'NS':
      return `${fqdn} ${safeTtl} IN NS ${dotTarget(record.target)}`;
    case 'SOA':
      return `${fqdn} ${safeTtl} IN SOA ${dotTarget(record.mname)} ${dotTarget(record.rname)} ${String(record.serial)} ${String(record.refresh)} ${String(record.retry)} ${String(record.expire)} ${String(record.minimum)}`;
    case 'CAA':
      return `${fqdn} ${safeTtl} IN CAA ${String(record.flags)} ${record.tag.trim() || 'issue'} "${record.value}"`;
    case 'TLSA':
      return `${fqdn} ${safeTtl} IN TLSA ${String(record.usage)} ${String(record.selector)} ${String(record.matching_type)} ${record.cert_data.trim().toLowerCase()}`;
    case 'SMIMEA':
      return `${fqdn} ${safeTtl} IN SMIMEA ${String(record.usage)} ${String(record.selector)} ${String(record.matching_type)} ${record.cert_data.trim().toLowerCase()}`;
    case 'SSHFP':
      return `${fqdn} ${safeTtl} IN SSHFP ${String(record.algorithm)} ${String(record.fp_type)} ${record.fingerprint.trim().toLowerCase()}`;
    case 'NAPTR':
      return `${fqdn} ${safeTtl} IN NAPTR ${String(record.order)} ${String(record.preference)} "${record.flags}" "${record.service}" "${record.regexp}" ${dotTarget(record.replacement)}`;
    case 'URI':
      return `${fqdn} ${safeTtl} IN URI ${String(record.priority)} ${String(record.weight)} "${record.target}"`;
    case 'LOC':
      return `${fqdn} ${safeTtl} IN LOC ${record.coordinates.trim()}`;
    case 'HINFO':
      return `${fqdn} ${safeTtl} IN HINFO "${record.cpu}" "${record.os}"`;
    case 'RP':
      return `${fqdn} ${safeTtl} IN RP ${dotTarget(record.mbox)} ${dotTarget(record.txt)}`;
    case 'DNAME':
      return `${fqdn} ${safeTtl} IN DNAME ${dotTarget(record.target)}`;
    case 'DS':
      return `${fqdn} ${safeTtl} IN DS ${String(record.key_tag)} ${String(record.algorithm)} ${String(record.digest_type)} ${record.digest.trim().toLowerCase()}`;
    case 'DNSKEY':
      return `${fqdn} ${safeTtl} IN DNSKEY ${String(record.flags)} ${String(record.protocol)} ${String(record.algorithm)} ${record.public_key.trim()}`;
    case 'OPENPGPKEY':
      return `${fqdn} ${safeTtl} IN OPENPGPKEY ${record.public_key.trim()}`;
    case 'CERT':
      return `${fqdn} ${safeTtl} IN CERT ${String(record.cert_type)} ${String(record.key_tag)} ${String(record.algorithm)} ${record.cert_data.trim()}`;
    case 'CSYNC':
      return `${fqdn} ${safeTtl} IN CSYNC ${String(record.soa_serial)} ${String(record.flags)} ${record.types.trim().toUpperCase()}`;
    case 'RAW': {
      const hex = record.rdata_hex.replace(/\s+/g, '').toLowerCase();
      return `${fqdn} ${safeTtl} IN TYPE${String(record.rr_type)} \\# ${String(Math.floor(hex.length / 2))} ${hex}`;
    }
    default:
      return assertNever(record);
  }
}

/**
 * Provides default initial RDATA values when the user switches record types in the modal.
 */
export function defaultRecordDataForType(rrType: DnsRecordType): LocalRecordData {
  switch (rrType) {
    case 'A':
      return { type: 'A', ip: '10.0.0.10', auto_ptr: false };
    case 'AAAA':
      return { type: 'AAAA', ip: '2001:db8::10', auto_ptr: false };
    case 'CNAME':
      return { type: 'CNAME', target: 'target.internal.corp' };
    case 'ANAME':
      return { type: 'ANAME', target: 'edge-lb.internal.corp' };
    case 'MX':
      return { type: 'MX', priority: 10, target: 'mail.internal.corp' };
    case 'TXT':
      return { type: 'TXT', content: 'v=spf1 -all' };
    case 'SPF':
      return { type: 'SPF', content: 'v=spf1 mx -all' };
    case 'SRV':
      return { type: 'SRV', priority: 10, weight: 5, port: 443, target: 'svc.internal.corp' };
    case 'HTTPS':
      return {
        type: 'HTTPS',
        priority: 1,
        target: '.',
        svc_params: 'alpn="h3,h2" ipv4hint=10.0.0.10'
      };
    case 'SVCB':
      return { type: 'SVCB', priority: 1, target: 'svc.internal.corp', svc_params: 'alpn="h2" port=8443' };
    case 'PTR':
      return { type: 'PTR', target: 'host.internal.corp' };
    case 'NS':
      return { type: 'NS', target: 'ns1.internal.corp' };
    case 'SOA':
      return {
        type: 'SOA',
        mname: 'ns1.internal.corp',
        rname: 'hostmaster.internal.corp',
        serial: 2026041701,
        refresh: 3600,
        retry: 600,
        expire: 604800,
        minimum: 300
      };
    case 'CAA':
      return { type: 'CAA', flags: 0, tag: 'issue', value: 'letsencrypt.org' };
    case 'TLSA':
      return {
        type: 'TLSA',
        usage: 3,
        selector: 1,
        matching_type: 1,
        cert_data: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      };
    case 'SMIMEA':
      return {
        type: 'SMIMEA',
        usage: 3,
        selector: 1,
        matching_type: 1,
        cert_data: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      };
    case 'SSHFP':
      return {
        type: 'SSHFP',
        algorithm: 4,
        fp_type: 2,
        fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      };
    case 'NAPTR':
      return {
        type: 'NAPTR',
        order: 100,
        preference: 10,
        flags: 'S',
        service: 'SIP+D2U',
        regexp: '',
        replacement: '_sip._udp.internal.corp'
      };
    case 'URI':
      return { type: 'URI', priority: 10, weight: 1, target: 'https://svc.internal.corp/api' };
    case 'LOC':
      return { type: 'LOC', coordinates: '37 46 29.744 N 122 25 9.816 W 15.00m' };
    case 'HINFO':
      return { type: 'HINFO', cpu: 'X86-64', os: 'LINUX' };
    case 'RP':
      return { type: 'RP', mbox: 'ops.internal.corp', txt: 'info.internal.corp' };
    case 'DNAME':
      return { type: 'DNAME', target: 'delegated.internal.corp' };
    case 'DS':
      return {
        type: 'DS',
        key_tag: 12345,
        algorithm: 13,
        digest_type: 2,
        digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      };
    case 'DNSKEY':
      return {
        type: 'DNSKEY',
        flags: 257,
        protocol: 3,
        algorithm: 13,
        public_key: 'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=='
      };
    case 'OPENPGPKEY':
      return {
        type: 'OPENPGPKEY',
        public_key: 'mQENBFVHm5sBCADBP2I0/8n4s4P1y7L0aB=='
      };
    case 'CERT':
      return {
        type: 'CERT',
        cert_type: 1,
        key_tag: 12345,
        algorithm: 13,
        cert_data: 'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=='
      };
    case 'CSYNC':
      return { type: 'CSYNC', soa_serial: 2026041701, flags: 1, types: 'A AAAA NS' };
    case 'RAW':
      return { type: 'RAW', rr_type: 65280, rdata_hex: 'c0000201' };
    default:
      return assertNever(rrType);
  }
}
