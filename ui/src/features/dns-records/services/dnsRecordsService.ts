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

const DeleteZoneResponseSchema = z
  .object({
    deleted: z.boolean().optional(),
    deleted_id: z.string().optional(),
    deleted_records: z.union([z.number().int().nonnegative(), z.boolean()]).optional(),
    deleted_records_count: z.number().int().nonnegative().optional()
  })
  .transform((data) => ({
    deleted: data.deleted ?? true,
    deleted_records:
      typeof data.deleted_records === 'number'
        ? data.deleted_records
        : (data.deleted_records_count ?? 0)
  }));

export const dnsRecordsService = {
  async listZones(): Promise<DnsZoneView[]> {
    const res = await httpClient.request('/api/v1/dns/zones', { method: 'GET' }, ZoneListResponseSchema);
    return res.items;
  },

  async createZone(payload: UpsertZonePayload): Promise<DnsZoneView> {
    return httpClient.request(
      '/api/v1/dns/zones',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      DnsZoneViewSchema
    );
  },

  async updateZone(id: ZoneId, payload: UpsertZonePayload): Promise<DnsZoneView> {
    return httpClient.request(
      `/api/v1/dns/zones/${encodeURIComponent(id)}`,
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
      `/api/v1/dns/zones/${encodeURIComponent(id)}?${params.toString()}`,
      { method: 'DELETE' },
      DeleteZoneResponseSchema
    );
  },

  async exportZoneBind(id: ZoneId): Promise<ZoneExportResponse> {
    return httpClient.request(
      `/api/v1/dns/zones/${encodeURIComponent(id)}/export`,
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
      `/api/v1/dns/records?${params.toString()}`,
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
      '/api/v1/dns/records/preview',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      RecordPreviewResponseSchema
    );
  },

  async createRecord(payload: UpsertRecordPayload): Promise<LocalDnsRecordView> {
    return httpClient.request(
      '/api/v1/dns/records',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      LocalDnsRecordViewSchema
    );
  },

  async updateRecord(id: RecordId, payload: UpsertRecordPayload): Promise<LocalDnsRecordView> {
    return httpClient.request(
      `/api/v1/dns/records/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload)
      },
      LocalDnsRecordViewSchema
    );
  },

  async deleteRecord(id: RecordId): Promise<void> {
    await httpClient.request(
      `/api/v1/dns/records/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
      z.object({
        deleted: z.boolean().optional(),
        deleted_id: z.string().optional()
      })
    );
  },

  async bulkImportRecords(payload: {
    format: 'json' | 'bind';
    zone_id?: string | null;
    bind_text?: string;
    default_ttl?: number;
    records?: UpsertRecordPayload[];
  }): Promise<BulkImportRecordsResponse> {
    if (payload.format === 'json' && payload.records !== undefined) {
      let importedCount = 0;
      const errors: string[] = [];
      for (const rec of payload.records) {
        try {
          await dnsRecordsService.createRecord(rec);
          importedCount += 1;
        } catch (err) {
          errors.push(err instanceof Error ? err.message : 'Failed to import record.');
        }
      }
      return {
        imported_count: importedCount,
        skipped_count: errors.length,
        errors
      };
    }

    return httpClient.request(
      '/api/v1/dns/records/import',
      {
        method: 'POST',
        body: JSON.stringify({
          zone_id: payload.zone_id ?? null,
          content: payload.bind_text ?? '',
          dry_run: false
        })
      },
      BulkImportRecordsResponseSchema
    );
  }
};
