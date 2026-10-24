import { httpClient } from '../../../services';
import type { PaginatedList } from '../../../types';
import {
  type AuditEventEntry,
  type DnsActivityEntry,
  PaginatedAuditEventsSchema,
  PaginatedDnsActivitySchema,
  type TelemetrySummaryResponse,
  TelemetrySummaryResponseSchema
} from '../types/telemetry.types';

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
    return httpClient.request(
      `/api/v1/telemetry/activity?${params.toString()}`,
      { method: 'GET' },
      PaginatedDnsActivitySchema
    );
  },

  async listAuditEvents(
    page = 1,
    perPage = 25
  ): Promise<PaginatedList<AuditEventEntry>> {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(Math.min(perPage, 100))
    });
    return httpClient.request(
      `/api/v1/telemetry/audit?${params.toString()}`,
      { method: 'GET' },
      PaginatedAuditEventsSchema
    );
  }
};
