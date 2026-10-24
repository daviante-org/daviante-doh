import { z } from 'zod';
import { httpClient } from '../../../services';
import type { PaginatedList } from '../../../types';
import {
  type AuditEventEntry,
  CombinedTelemetryActivitySchema,
  type DnsActivityEntry,
  PaginatedAuditEventsSchema,
  PaginatedDnsActivitySchema,
  type TelemetrySummaryResponse,
  TelemetrySummaryResponseSchema
} from '../types/telemetry.types';

const ActivityOrCombinedSchema = z.union([
  PaginatedDnsActivitySchema,
  CombinedTelemetryActivitySchema
]);

const AuditOrCombinedSchema = z.union([
  PaginatedAuditEventsSchema,
  CombinedTelemetryActivitySchema
]);

export const telemetryService = {
  async getTelemetrySummary(): Promise<TelemetrySummaryResponse> {
    return httpClient.request(
      '/api/v1/telemetry/summary',
      { method: 'GET' },
      TelemetrySummaryResponseSchema
    );
  },

  async listActivity(
    page = 1,
    perPage = 25,
    search = ''
  ): Promise<PaginatedList<DnsActivityEntry>> {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(Math.min(perPage, 100))
    });
    if (search.trim().length > 0) {
      params.set('search', search.trim());
    }
    const res = await httpClient.request(
      `/api/v1/telemetry/activity?${params.toString()}`,
      { method: 'GET' },
      ActivityOrCombinedSchema
    );
    if ('items' in res) {
      return res;
    }
    const query = search.trim().toLowerCase();
    const filtered =
      query.length === 0
        ? res.dns_activity
        : res.dns_activity.filter(
            (e) =>
              e.question_name.toLowerCase().includes(query) ||
              e.outcome.toLowerCase().includes(query) ||
              e.question_type.toLowerCase().includes(query)
          );
    const offset = (page - 1) * perPage;
    return {
      items: filtered.slice(offset, offset + perPage),
      total: filtered.length,
      page,
      per_page: perPage
    };
  },

  async listAuditEvents(
    page = 1,
    perPage = 25
  ): Promise<PaginatedList<AuditEventEntry>> {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(Math.min(perPage, 100))
    });
    const res = await httpClient.request(
      `/api/v1/telemetry/activity?${params.toString()}`,
      { method: 'GET' },
      AuditOrCombinedSchema
    );
    if ('items' in res) {
      return res;
    }
    const offset = (page - 1) * perPage;
    return {
      items: res.admin_audit.slice(offset, offset + perPage),
      total: res.admin_audit.length,
      page,
      per_page: perPage
    };
  }
};
