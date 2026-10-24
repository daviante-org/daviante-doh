import { z } from 'zod';
import { DNS_RECORD_TYPES } from '../../../constants';
import { isValidDnsDomain, isValidIpv4, isValidIpv6 } from '../../../utils';

export const DnsLookupRecordItemSchema = z.object({
  name: z.string(),
  rr_type: z.string(),
  ttl: z.number().int().nonnegative(),
  rdata: z.string()
});
export type DnsLookupRecordItem = z.infer<typeof DnsLookupRecordItemSchema>;

export interface DnsLookupResponse {
  question_name: string;
  question_type: string;
  response_code: string;
  resolution_source: string;
  latency_ms: number;
  authenticated_data: boolean;
  checking_disabled: boolean;
  answers: DnsLookupRecordItem[];
  authorities: DnsLookupRecordItem[];
  additionals: DnsLookupRecordItem[];
}

const RawDnsJsonRrSchema = z.object({
  name: z.string(),
  type: z.number().int(),
  TTL: z.number().int().nonnegative().optional(),
  data: z.string()
});

const RawDnsJsonDocumentSchema = z
  .object({
    AD: z.boolean().optional(),
    CD: z.boolean().optional(),
    Answer: z.array(RawDnsJsonRrSchema).optional(),
    Authority: z.array(RawDnsJsonRrSchema).optional(),
    Additional: z.array(RawDnsJsonRrSchema).optional()
  })
  .nullable()
  .optional();

function mapCodeToTypeName(code: number, fallback: string): string {
  const table: Record<number, string> = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    13: 'HINFO',
    15: 'MX',
    16: 'TXT',
    17: 'RP',
    28: 'AAAA',
    29: 'LOC',
    33: 'SRV',
    35: 'NAPTR',
    37: 'CERT',
    39: 'DNAME',
    43: 'DS',
    44: 'SSHFP',
    48: 'DNSKEY',
    52: 'TLSA',
    53: 'SMIMEA',
    61: 'OPENPGPKEY',
    64: 'SVCB',
    65: 'HTTPS',
    99: 'SPF',
    256: 'URI',
    257: 'CAA'
  };
  return table[code] ?? fallback;
}

export const DnsLookupResponseSchema: z.ZodType<DnsLookupResponse> = z
  .object({
    question_name: z.string().optional(),
    qname: z.string().optional(),
    question_type: z.string().optional(),
    record_type: z.string().optional(),
    response_code: z.string().optional(),
    rcode_name: z.string().optional(),
    resolution_source: z.string().optional(),
    source: z.string().optional(),
    latency_ms: z.number().nonnegative(),
    authenticated_data: z.boolean().optional(),
    checking_disabled: z.boolean().optional(),
    answers: z.array(DnsLookupRecordItemSchema).optional(),
    authorities: z.array(DnsLookupRecordItemSchema).optional(),
    additionals: z.array(DnsLookupRecordItemSchema).optional(),
    dns_json: RawDnsJsonDocumentSchema
  })
  .transform((raw): DnsLookupResponse => {
    const qtypeStr = raw.question_type ?? raw.record_type ?? 'A';
    const mapSection = (
      items: Array<z.infer<typeof RawDnsJsonRrSchema>> | undefined
    ): DnsLookupRecordItem[] =>
      (items ?? []).map((item) => ({
        name: item.name,
        rr_type: mapCodeToTypeName(item.type, qtypeStr),
        ttl: item.TTL ?? 0,
        rdata: item.data
      }));

    return {
      question_name: raw.question_name ?? raw.qname ?? '',
      question_type: qtypeStr,
      response_code: raw.response_code ?? raw.rcode_name ?? 'NOERROR',
      resolution_source: raw.resolution_source ?? raw.source ?? 'upstream',
      latency_ms: raw.latency_ms,
      authenticated_data: raw.authenticated_data ?? raw.dns_json?.AD ?? false,
      checking_disabled: raw.checking_disabled ?? raw.dns_json?.CD ?? false,
      answers: raw.answers ?? mapSection(raw.dns_json?.Answer),
      authorities: raw.authorities ?? mapSection(raw.dns_json?.Authority),
      additionals: raw.additionals ?? mapSection(raw.dns_json?.Additional)
    };
  });

export const DnsLookupFormSchema = z.object({
  domain: z
    .string()
    .trim()
    .min(1, 'Domain name is required.')
    .max(253, 'Domain name must not exceed 253 characters.')
    .refine((val) => isValidDnsDomain(val, false) || isValidIpv4(val) || isValidIpv6(val), {
      message: 'Enter a valid domain name (e.g., example.com) or IP address for PTR lookup.'
    }),
  rr_type: z.enum(DNS_RECORD_TYPES),
  dnssec_do: z.boolean(),
  checking_disabled: z.boolean()
});
export type DnsLookupFormValues = z.infer<typeof DnsLookupFormSchema>;

export interface LookupRecordSectionTableProps {
  readonly title: string;
  readonly records: readonly DnsLookupRecordItem[];
}

export interface LookupResultSummaryCardProps {
  readonly result: DnsLookupResponse;
}

export interface LookupJsonPayloadCardProps {
  readonly result: DnsLookupResponse;
}
