import { z } from 'zod';
import { httpClient } from '../../../services';
import type { PaginatedList, RecordId, ZoneId } from '../../../types';
import {
  type BulkImportRecordsResponse,
  BulkImportRecordsResponseSchema,
  type DnsZoneView,
  DnsZoneViewSchema,
  type LocalDnsRecordView,
  LocalDnsRecordViewSchema,
  type LocalRecordData,
  PaginatedLocalDnsRecordsSchema,
  type RecordPreviewResponse,
  RecordPreviewResponseSchema,
  type UpsertRecordPayload,
  type UpsertZonePayload,
  type ZoneExportResponse,
  ZoneExportResponseSchema,
  ZoneListResponseSchema
} from '../types/dnsRecords.types';

export const dnsRecordsService = {
  async listZones(): Promise<DnsZoneView[]> {
    const res = await httpClient.request('/api/v1/zones', { method: 'GET' }, ZoneListResponseSchema);
    return res.items;
  },

  async createZone(payload: UpsertZonePayload): Promise<DnsZoneView> {
    return httpClient.request(
      '/api/v1/zones',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      DnsZoneViewSchema
    );
  },

  async updateZone(id: ZoneId, payload: UpsertZonePayload): Promise<DnsZoneView> {
    return httpClient.request(
      `/api/v1/zones/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload)
      },
      DnsZoneViewSchema
    );
  },

  async deleteZone(
    id: ZoneId,
    deleteRecords = false
  ): Promise<{ deleted: boolean; deleted_records: number }> {
    const params = new URLSearchParams({
      delete_records: deleteRecords ? 'true' : 'false'
    });
    return httpClient.request(
      `/api/v1/zones/${encodeURIComponent(id)}?${params.toString()}`,
      { method: 'DELETE' },
      z.object({ deleted: z.boolean(), deleted_records: z.number().int().nonnegative() })
    );
  },

  async exportZoneBind(id: ZoneId): Promise<ZoneExportResponse> {
    return httpClient.request(
      `/api/v1/zones/${encodeURIComponent(id)}/export`,
      { method: 'GET' },
      ZoneExportResponseSchema
    );
  },

  async listRecords(
    page = 1,
    perPage = 20,
    search = '',
    recordType = '',
    enabledFilter: 'all' | 'enabled' | 'disabled' = 'all',
    zoneId = ''
  ): Promise<PaginatedList<LocalDnsRecordView>> {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(Math.min(perPage, 100))
    });
    if (search.trim().length > 0) {
      params.set('search', search.trim());
    }
    if (recordType.trim().length > 0) {
      params.set('record_type', recordType.trim());
    }
    if (enabledFilter === 'enabled') {
      params.set('enabled', 'true');
    } else if (enabledFilter === 'disabled') {
      params.set('enabled', 'false');
    }
    if (zoneId.trim().length > 0) {
      params.set('zone_id', zoneId.trim());
    }
    return httpClient.request(
      `/api/v1/records?${params.toString()}`,
      { method: 'GET' },
      PaginatedLocalDnsRecordsSchema
    );
  },

  async previewRecord(payload: {
    zone_id?: string | null;
    domain: string;
    ttl: number;
    enabled: boolean;
    comment: string;
    record: LocalRecordData;
  }): Promise<RecordPreviewResponse> {
    return httpClient.request(
      '/api/v1/records/preview',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      RecordPreviewResponseSchema
    );
  },

  async createRecord(payload: UpsertRecordPayload): Promise<LocalDnsRecordView> {
    return httpClient.request(
      '/api/v1/records',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      LocalDnsRecordViewSchema
    );
  },

  async updateRecord(id: RecordId, payload: UpsertRecordPayload): Promise<LocalDnsRecordView> {
    return httpClient.request(
      `/api/v1/records/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload)
      },
      LocalDnsRecordViewSchema
    );
  },

  async deleteRecord(id: RecordId): Promise<void> {
    await httpClient.request(
      `/api/v1/records/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
      z.object({ deleted: z.boolean() })
    );
  },

  async bulkImportRecords(payload: {
    format: 'json' | 'bind';
    zone_id?: string | null;
    bind_text?: string;
    default_ttl?: number;
    records?: UpsertRecordPayload[];
  }): Promise<BulkImportRecordsResponse> {
    return httpClient.request(
      '/api/v1/records/import',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      BulkImportRecordsResponseSchema
    );
  }
};
