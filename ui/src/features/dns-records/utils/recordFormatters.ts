import type { DnsRecordType, RecordCategoryFilter } from '../../../constants';
import { assertNever } from '../../../utils';
import type { LocalRecordData } from '../types/dnsRecords.types';

export type RecordBadgeColor =
  | 'blue'
  | 'teal'
  | 'purple'
  | 'orange'
  | 'green'
  | 'yellow'
  | 'grey'
  | 'red';

export function getRecordTypeColor(rrType: DnsRecordType): RecordBadgeColor {
  switch (rrType) {
    case 'A':
    case 'AAAA':
      return 'blue';
    case 'CNAME':
    case 'ANAME':
    case 'DNAME':
    case 'PTR':
      return 'teal';
    case 'MX':
    case 'TXT':
    case 'SPF':
      return 'purple';
    case 'SRV':
    case 'HTTPS':
    case 'SVCB':
    case 'NAPTR':
    case 'URI':
      return 'orange';
    case 'CAA':
    case 'TLSA':
    case 'SMIMEA':
    case 'SSHFP':
    case 'DS':
    case 'DNSKEY':
    case 'OPENPGPKEY':
    case 'CERT':
    case 'CSYNC':
      return 'green';
    case 'NS':
    case 'SOA':
      return 'yellow';
    case 'LOC':
    case 'HINFO':
    case 'RP':
    case 'RAW':
      return 'grey';
    default:
      return assertNever(rrType);
  }
}

export function matchesCategoryFilter(
  rrType: DnsRecordType,
  category: RecordCategoryFilter
): boolean {
  switch (category) {
    case 'ALL':
      return true;
    case 'ADDRESS':
      return (
        rrType === 'A' ||
        rrType === 'AAAA' ||
        rrType === 'CNAME' ||
        rrType === 'ANAME' ||
        rrType === 'DNAME' ||
        rrType === 'PTR'
      );
    case 'MAIL_TEXT':
      return rrType === 'MX' || rrType === 'TXT' || rrType === 'SPF';
    case 'SERVICE':
      return (
        rrType === 'SRV' ||
        rrType === 'HTTPS' ||
        rrType === 'SVCB' ||
        rrType === 'NAPTR' ||
        rrType === 'URI'
      );
    case 'SECURITY':
      return (
        rrType === 'CAA' ||
        rrType === 'TLSA' ||
        rrType === 'SMIMEA' ||
        rrType === 'SSHFP' ||
        rrType === 'DS' ||
        rrType === 'DNSKEY' ||
        rrType === 'OPENPGPKEY' ||
        rrType === 'CERT' ||
        rrType === 'CSYNC'
      );
    case 'INFRA':
      return (
        rrType === 'NS' ||
        rrType === 'SOA' ||
        rrType === 'LOC' ||
        rrType === 'HINFO' ||
        rrType === 'RP' ||
        rrType === 'RAW'
      );
    default:
      return assertNever(category);
  }
}

export interface ValueSummaryResult {
  readonly primary: string;
  readonly badge?: string;
}

export function formatRecordValueSummary(rec: LocalRecordData): ValueSummaryResult {
  switch (rec.type) {
    case 'A':
    case 'AAAA':
      return rec.auto_ptr
        ? { primary: rec.ip, badge: 'Auto-PTR' }
        : { primary: rec.ip };
    case 'CNAME':
    case 'ANAME':
    case 'DNAME':
    case 'NS':
    case 'PTR':
      return { primary: rec.target };
    case 'MX':
      return { primary: rec.target, badge: `Prio ${String(rec.priority)}` };
    case 'TXT':
    case 'SPF':
      return {
        primary: rec.content.length > 72 ? `${rec.content.slice(0, 72)}…` : rec.content
      };
    case 'SRV':
      return {
        primary: `${rec.target}:${String(rec.port)}`,
        badge: `Prio ${String(rec.priority)} · Wt ${String(rec.weight)}`
      };
    case 'HTTPS':
    case 'SVCB':
      return {
        primary: `${rec.target} ${rec.svc_params}`.trim(),
        badge: rec.priority === 0 ? 'AliasMode (0)' : `Prio ${String(rec.priority)}`
      };
    case 'URI':
      return {
        primary: rec.target,
        badge: `Prio ${String(rec.priority)} · Wt ${String(rec.weight)}`
      };
    case 'CAA':
      return {
        primary: `${rec.tag} "${rec.value}"`,
        badge: rec.flags === 128 ? 'Critical (128)' : 'Flags 0'
      };
    case 'SOA':
      return {
        primary: `${rec.mname} (${rec.rname})`,
        badge: `Serial ${String(rec.serial)}`
      };
    case 'TLSA':
    case 'SMIMEA':
      return {
        primary: `${rec.cert_data.slice(0, 28)}…`,
        badge: `${String(rec.usage)}/${String(rec.selector)}/${String(rec.matching_type)}`
      };
    case 'SSHFP':
      return {
        primary: `${rec.fingerprint.slice(0, 28)}…`,
        badge: `Alg ${String(rec.algorithm)} · FP ${String(rec.fp_type)}`
      };
    case 'DS':
      return {
        primary: `${rec.digest.slice(0, 28)}…`,
        badge: `KeyTag ${String(rec.key_tag)} · Alg ${String(rec.algorithm)}`
      };
    case 'DNSKEY':
      return {
        primary: `${rec.public_key.slice(0, 28)}…`,
        badge: `Flags ${String(rec.flags)} · Alg ${String(rec.algorithm)}`
      };
    case 'OPENPGPKEY':
      return {
        primary: `${rec.public_key.slice(0, 32)}…`,
        badge: 'OpenPGP'
      };
    case 'CERT':
      return {
        primary: `${rec.cert_data.slice(0, 28)}…`,
        badge: `Type ${String(rec.cert_type)} · KeyTag ${String(rec.key_tag)}`
      };
    case 'CSYNC':
      return {
        primary: rec.types,
        badge: `SOA ${String(rec.soa_serial)}`
      };
    case 'NAPTR':
      return {
        primary: `${rec.service} → ${rec.replacement}`,
        badge: `Ord ${String(rec.order)} · Pref ${String(rec.preference)}`
      };
    case 'LOC':
      return { primary: rec.coordinates };
    case 'HINFO':
      return { primary: `${rec.cpu} / ${rec.os}` };
    case 'RP':
      return { primary: `${rec.mbox} (${rec.txt})` };
    case 'RAW':
      return {
        primary: rec.rdata_hex,
        badge: `TYPE${String(rec.rr_type)}`
      };
    default:
      return assertNever(rec);
  }
}

export interface RdataFieldPair {
  readonly label: string;
  readonly value: string;
}

export function getRecordRdataBreakdown(rec: LocalRecordData): readonly RdataFieldPair[] {
  switch (rec.type) {
    case 'A':
    case 'AAAA':
      return [
        { label: 'IP Address', value: rec.ip },
        { label: 'Automatic Reverse PTR', value: rec.auto_ptr ? 'Enabled' : 'Disabled' }
      ];
    case 'CNAME':
    case 'ANAME':
    case 'DNAME':
    case 'NS':
    case 'PTR':
      return [{ label: 'Target FQDN', value: rec.target }];
    case 'MX':
      return [
        { label: 'Preference / Priority', value: String(rec.priority) },
        { label: 'Mail Server Target', value: rec.target }
      ];
    case 'TXT':
    case 'SPF':
      return [{ label: 'Text Payload', value: rec.content }];
    case 'SRV':
      return [
        { label: 'Priority', value: String(rec.priority) },
        { label: 'Weight', value: String(rec.weight) },
        { label: 'Port', value: String(rec.port) },
        { label: 'Target Host', value: rec.target }
      ];
    case 'HTTPS':
    case 'SVCB':
      return [
        { label: 'SvcPriority', value: String(rec.priority) },
        { label: 'TargetName', value: rec.target },
        { label: 'SvcParams', value: rec.svc_params || '(none)' }
      ];
    case 'URI':
      return [
        { label: 'Priority', value: String(rec.priority) },
        { label: 'Weight', value: String(rec.weight) },
        { label: 'Target URI', value: rec.target }
      ];
    case 'CAA':
      return [
        { label: 'Flags', value: String(rec.flags) },
        { label: 'Property Tag', value: rec.tag },
        { label: 'CA Value', value: rec.value }
      ];
    case 'SOA':
      return [
        { label: 'Primary NS (MNAME)', value: rec.mname },
        { label: 'Admin Mailbox (RNAME)', value: rec.rname },
        { label: 'Serial', value: String(rec.serial) },
        {
          label: 'Timers (Refresh / Retry / Expire / Min)',
          value: `${String(rec.refresh)}s / ${String(rec.retry)}s / ${String(rec.expire)}s / ${String(rec.minimum)}s`
        }
      ];
    case 'TLSA':
    case 'SMIMEA':
      return [
        { label: 'Cert Usage', value: String(rec.usage) },
        { label: 'Selector', value: String(rec.selector) },
        { label: 'Matching Type', value: String(rec.matching_type) },
        { label: 'Certificate Association Hex', value: rec.cert_data }
      ];
    case 'SSHFP':
      return [
        { label: 'Algorithm', value: String(rec.algorithm) },
        { label: 'Fingerprint Type', value: String(rec.fp_type) },
        { label: 'Hex Fingerprint', value: rec.fingerprint }
      ];
    case 'DS':
      return [
        { label: 'Key Tag', value: String(rec.key_tag) },
        { label: 'Algorithm', value: String(rec.algorithm) },
        { label: 'Digest Type', value: String(rec.digest_type) },
        { label: 'Hex Digest', value: rec.digest }
      ];
    case 'DNSKEY':
      return [
        { label: 'Flags', value: String(rec.flags) },
        { label: 'Protocol', value: String(rec.protocol) },
        { label: 'Algorithm', value: String(rec.algorithm) },
        { label: 'Public Key (Base64)', value: rec.public_key }
      ];
    case 'OPENPGPKEY':
      return [{ label: 'Public Key (Base64)', value: rec.public_key }];
    case 'CERT':
      return [
        { label: 'Certificate Type', value: String(rec.cert_type) },
        { label: 'Key Tag', value: String(rec.key_tag) },
        { label: 'Algorithm', value: String(rec.algorithm) },
        { label: 'Certificate Data (Base64)', value: rec.cert_data }
      ];
    case 'CSYNC':
      return [
        { label: 'SOA Serial', value: String(rec.soa_serial) },
        { label: 'Flags', value: String(rec.flags) },
        { label: 'Synchronized RR Types', value: rec.types }
      ];
    case 'NAPTR':
      return [
        { label: 'Order / Preference', value: `${String(rec.order)} / ${String(rec.preference)}` },
        { label: 'Flags / Service', value: `${rec.flags} / ${rec.service}` },
        { label: 'Regexp', value: rec.regexp || '(none)' },
        { label: 'Replacement', value: rec.replacement }
      ];
    case 'LOC':
      return [{ label: 'WGS84 Coordinates (RFC 1876)', value: rec.coordinates }];
    case 'HINFO':
      return [
        { label: 'CPU Architecture', value: rec.cpu },
        { label: 'Operating System', value: rec.os }
      ];
    case 'RP':
      return [
        { label: 'Responsible Mailbox (MBOX)', value: rec.mbox },
        { label: 'TXT Record Pointer', value: rec.txt }
      ];
    case 'RAW':
      return [
        { label: 'IANA RR Type Code', value: `TYPE${String(rec.rr_type)}` },
        { label: 'Wire RDATA Hex (RFC 3597)', value: rec.rdata_hex }
      ];
    default:
      return assertNever(rec);
  }
}

export function formatOwnerParts(
  domain: string,
  zoneName?: string | null
): { readonly primaryLabel: string; readonly zoneSuffix: string | null } {
  if (!zoneName) {
    return { primaryLabel: domain, zoneSuffix: null };
  }
  const lowerDom = domain.toLowerCase();
  const lowerZone = zoneName.toLowerCase();
  if (lowerDom === lowerZone) {
    return { primaryLabel: '@ (Apex)', zoneSuffix: `.${zoneName}` };
  }
  if (lowerDom.endsWith(`.${lowerZone}`)) {
    const sub = domain.slice(0, domain.length - zoneName.length - 1);
    return { primaryLabel: sub, zoneSuffix: `.${zoneName}` };
  }
  return { primaryLabel: domain, zoneSuffix: null };
}
