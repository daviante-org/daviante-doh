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

export const DnsLookupResponseSchema = z.object({
  question_name: z.string(),
  question_type: z.string(),
  response_code: z.string(),
  resolution_source: z.string(),
  latency_ms: z.number().nonnegative(),
  authenticated_data: z.boolean(),
  checking_disabled: z.boolean(),
  answers: z.array(DnsLookupRecordItemSchema),
  authorities: z.array(DnsLookupRecordItemSchema),
  additionals: z.array(DnsLookupRecordItemSchema)
});
export type DnsLookupResponse = z.infer<typeof DnsLookupResponseSchema>;

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
