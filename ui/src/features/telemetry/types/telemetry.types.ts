import { z } from 'zod';
import { createPaginatedSchema } from '../../../types';

export const UpstreamHealthStatusSchema = z.object({
  address: z.string(),
  healthy: z.boolean()
});
export type UpstreamHealthStatus = z.infer<typeof UpstreamHealthStatusSchema>;

export const TelemetrySummaryResponseSchema = z.object({
  total_queries: z.number().int().nonnegative(),
  cache_hits: z.number().int().nonnegative(),
  cache_misses: z.number().int().nonnegative(),
  cache_hit_ratio_percent: z.number().nonnegative(),
  local_overrides: z.number().int().nonnegative(),
  policy_blocks: z.number().int().nonnegative(),
  rebinding_blocks: z.number().int().nonnegative(),
  upstream_Forwards: z.number().int().nonnegative(),
  upstream_failures: z.number().int().nonnegative(),
  rate_limited_queries: z.number().int().nonnegative(),
  active_local_records: z.number().int().nonnegative(),
  active_zones: z.number().int().nonnegative().optional(),
  active_policy_rules: z.number().int().nonnegative(),
  upstreams: z.array(UpstreamHealthStatusSchema)
});
export type TelemetrySummaryResponse = z.infer<typeof TelemetrySummaryResponseSchema>;

export const DnsActivityEntrySchema = z.object({
  timestamp_epoch: z.number().int().nonnegative(),
  client_ip: z.string(),
  question_name: z.string(),
  question_type: z.string(),
  outcome: z.string(),
  response_code: z.string(),
  latency_ms: z.number().nonnegative()
});
export type DnsActivityEntry = z.infer<typeof DnsActivityEntrySchema>;

export const PaginatedDnsActivitySchema = createPaginatedSchema(DnsActivityEntrySchema);

export const AuditEventEntrySchema = z.object({
  timestamp_epoch: z.number().int().nonnegative(),
  actor: z.string(),
  role: z.string(),
  action: z.string(),
  target: z.string(),
  outcome: z.string()
});
export type AuditEventEntry = z.infer<typeof AuditEventEntrySchema>;

export const PaginatedAuditEventsSchema = createPaginatedSchema(AuditEventEntrySchema);
