import { z } from 'zod';
import { createPaginatedSchema } from '../../../types';

export const UpstreamHealthStatusSchema = z.object({
  address: z.string(),
  healthy: z.boolean()
});
export type UpstreamHealthStatus = z.infer<typeof UpstreamHealthStatusSchema>;

export interface TelemetrySummaryResponse {
  total_queries: number;
  cache_hits: number;
  cache_misses: number;
  cache_hit_ratio_percent: number;
  local_overrides: number;
  policy_blocks: number;
  rebinding_blocks: number;
  upstream_Forwards: number;
  upstream_failures: number;
  rate_limited_queries: number;
  active_local_records: number;
  active_zones?: number;
  active_policy_rules: number;
  upstreams: UpstreamHealthStatus[];
}

export const TelemetrySummaryResponseSchema: z.ZodType<TelemetrySummaryResponse> = z
  .object({
    total_queries: z.number().int().nonnegative().optional(),
    requests_wire_total: z.number().int().nonnegative().optional(),
    requests_json_total: z.number().int().nonnegative().optional(),
    requests_odoh_total: z.number().int().nonnegative().optional(),
    cache_hits: z.number().int().nonnegative().optional(),
    cache_hits_total: z.number().int().nonnegative().optional(),
    cache_misses: z.number().int().nonnegative().optional(),
    cache_misses_total: z.number().int().nonnegative().optional(),
    cache_hit_ratio_percent: z.number().nonnegative().optional(),
    local_overrides: z.number().int().nonnegative().optional(),
    hosts_hits_total: z.number().int().nonnegative().optional(),
    policy_blocks: z.number().int().nonnegative().optional(),
    policy_blocked_total: z.number().int().nonnegative().optional(),
    rebinding_blocks: z.number().int().nonnegative().optional(),
    rebinding_blocked_total: z.number().int().nonnegative().optional(),
    upstream_Forwards: z.number().int().nonnegative().optional(),
    upstream_udp_total: z.number().int().nonnegative().optional(),
    upstream_tcp_total: z.number().int().nonnegative().optional(),
    upstream_dot_total: z.number().int().nonnegative().optional(),
    upstream_failures: z.number().int().nonnegative().optional(),
    upstream_failures_total: z.number().int().nonnegative().optional(),
    rate_limited_queries: z.number().int().nonnegative().optional(),
    rate_limited_total: z.number().int().nonnegative().optional(),
    active_local_records: z.number().int().nonnegative().optional(),
    local_records_count: z.number().int().nonnegative().optional(),
    active_zones: z.number().int().nonnegative().optional(),
    zones_count: z.number().int().nonnegative().optional(),
    active_policy_rules: z.number().int().nonnegative().optional(),
    allow_rules_count: z.number().int().nonnegative().optional(),
    block_rules_count: z.number().int().nonnegative().optional(),
    upstreams: z.array(UpstreamHealthStatusSchema)
  })
  .transform((raw): TelemetrySummaryResponse => {
    const totalQueries =
      raw.total_queries ??
      (raw.requests_wire_total ?? 0) +
        (raw.requests_json_total ?? 0) +
        (raw.requests_odoh_total ?? 0);
    const cacheHits = raw.cache_hits ?? raw.cache_hits_total ?? 0;
    const cacheMisses = raw.cache_misses ?? raw.cache_misses_total ?? 0;
    const cacheTotal = cacheHits + cacheMisses;
    const hitRatio =
      raw.cache_hit_ratio_percent ?? (cacheTotal > 0 ? (cacheHits / cacheTotal) * 100 : 0);

    return {
      total_queries: totalQueries,
      cache_hits: cacheHits,
      cache_misses: cacheMisses,
      cache_hit_ratio_percent: hitRatio,
      local_overrides: raw.local_overrides ?? raw.hosts_hits_total ?? 0,
      policy_blocks: raw.policy_blocks ?? raw.policy_blocked_total ?? 0,
      rebinding_blocks: raw.rebinding_blocks ?? raw.rebinding_blocked_total ?? 0,
      upstream_Forwards:
        raw.upstream_Forwards ??
        (raw.upstream_udp_total ?? 0) +
          (raw.upstream_tcp_total ?? 0) +
          (raw.upstream_dot_total ?? 0),
      upstream_failures: raw.upstream_failures ?? raw.upstream_failures_total ?? 0,
      rate_limited_queries: raw.rate_limited_queries ?? raw.rate_limited_total ?? 0,
      active_local_records: raw.active_local_records ?? raw.local_records_count ?? 0,
      active_zones: raw.active_zones ?? raw.zones_count ?? 0,
      active_policy_rules:
        raw.active_policy_rules ?? (raw.allow_rules_count ?? 0) + (raw.block_rules_count ?? 0),
      upstreams: raw.upstreams
    };
  });

export interface DnsActivityEntry {
  timestamp_epoch: number;
  client_ip: string;
  question_name: string;
  question_type: string;
  outcome: string;
  response_code: string;
  latency_ms: number;
}

export const DnsActivityEntrySchema: z.ZodType<DnsActivityEntry> = z
  .object({
    timestamp_epoch: z.number().int().nonnegative(),
    client_ip: z.string().optional(),
    question_name: z.string().optional(),
    qname: z.string().optional(),
    question_type: z.string().optional(),
    qtype: z.string().optional(),
    outcome: z.string(),
    response_code: z.string().optional(),
    rcode: z.string().optional(),
    latency_ms: z.number().nonnegative()
  })
  .transform((raw): DnsActivityEntry => ({
    timestamp_epoch: raw.timestamp_epoch,
    client_ip: raw.client_ip ?? 'redacted',
    question_name: raw.question_name ?? raw.qname ?? '',
    question_type: raw.question_type ?? raw.qtype ?? 'A',
    outcome: raw.outcome,
    response_code: raw.response_code ?? raw.rcode ?? 'NOERROR',
    latency_ms: raw.latency_ms
  }));

export const PaginatedDnsActivitySchema = createPaginatedSchema(DnsActivityEntrySchema);

export interface AuditEventEntry {
  timestamp_epoch: number;
  actor: string;
  role: string;
  action: string;
  target: string;
  outcome: string;
}

export const AuditEventEntrySchema: z.ZodType<AuditEventEntry> = z
  .object({
    timestamp_epoch: z.number().int().nonnegative(),
    actor: z.string().optional(),
    username: z.string().optional(),
    role: z.string(),
    action: z.string(),
    target: z.string(),
    outcome: z.string().optional(),
    detail: z.string().optional()
  })
  .transform((raw): AuditEventEntry => ({
    timestamp_epoch: raw.timestamp_epoch,
    actor: raw.actor ?? raw.username ?? 'admin',
    role: raw.role,
    action: raw.action,
    target: raw.target,
    outcome: raw.outcome ?? raw.detail ?? 'OK'
  }));

export const PaginatedAuditEventsSchema = createPaginatedSchema(AuditEventEntrySchema);

export const CombinedTelemetryActivitySchema = z.object({
  dns_activity: z.array(DnsActivityEntrySchema),
  admin_audit: z.array(AuditEventEntrySchema)
});
