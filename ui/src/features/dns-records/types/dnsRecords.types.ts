import { z } from 'zod';
import {
  type AdminRole,
  createPaginatedSchema,
  type RecordId,
  RecordIdSchema,
  ZoneIdSchema
} from '../../../types';

export const ZoneModeSchema = z.enum(['override', 'authoritative']);
export type ZoneMode = z.infer<typeof ZoneModeSchema>;

export const DnsZoneViewSchema = z.object({
  id: ZoneIdSchema,
  name: z.string().min(1).max(255),
  mode: ZoneModeSchema,
  primary_ns: z.string(),
  admin_email: z.string(),
  serial: z.number().int().nonnegative(),
  refresh: z.number().int().positive(),
  retry: z.number().int().positive(),
  expire: z.number().int().positive(),
  minimum: z.number().int().positive(),
  default_ttl: z.number().int().min(1).max(604800),
  enabled: z.boolean(),
  comment: z.string(),
  updated_at_epoch: z.number().int().nonnegative(),
  record_count: z.number().int().nonnegative()
});
export type DnsZoneView = z.infer<typeof DnsZoneViewSchema>;

export const ZoneListResponseSchema = z.object({
  items: z.array(DnsZoneViewSchema)
});

export const UpsertZonePayloadSchema = z.object({
  name: z.string().min(1).max(253),
  mode: ZoneModeSchema,
  primary_ns: z.string().min(1).max(253),
  admin_email: z.string().min(1).max(253),
  refresh: z.number().int().min(60).max(604800),
  retry: z.number().int().min(60).max(604800),
  expire: z.number().int().min(300).max(2419200),
  minimum: z.number().int().min(1).max(86400),
  default_ttl: z.number().int().min(1).max(604800),
  enabled: z.boolean(),
  comment: z.string().max(256)
});
export type UpsertZonePayload = z.infer<typeof UpsertZonePayloadSchema>;

export const ZoneExportResponseSchema = z.object({
  zone_id: z.string(),
  zone_name: z.string(),
  bind_zone_file: z.string()
});
export type ZoneExportResponse = z.infer<typeof ZoneExportResponseSchema>;

const RecordASchema = z.object({
  type: z.literal('A'),
  ip: z.string(),
  auto_ptr: z.boolean()
});

const RecordAAAASchema = z.object({
  type: z.literal('AAAA'),
  ip: z.string(),
  auto_ptr: z.boolean()
});

const RecordCNAMESchema = z.object({
  type: z.literal('CNAME'),
  target: z.string()
});

const RecordANAMESchema = z.object({
  type: z.literal('ANAME'),
  target: z.string()
});

const RecordMXSchema = z.object({
  type: z.literal('MX'),
  priority: z.number().int().min(0).max(65535),
  target: z.string()
});

const RecordTXTSchema = z.object({
  type: z.literal('TXT'),
  content: z.string()
});

const RecordSPFSchema = z.object({
  type: z.literal('SPF'),
  content: z.string()
});

const RecordSRVSchema = z.object({
  type: z.literal('SRV'),
  priority: z.number().int().min(0).max(65535),
  weight: z.number().int().min(0).max(65535),
  port: z.number().int().min(1).max(65535),
  target: z.string()
});

const RecordHTTPSSchema = z.object({
  type: z.literal('HTTPS'),
  priority: z.number().int().min(0).max(65535),
  target: z.string(),
  svc_params: z.string()
});

const RecordSVCBSchema = z.object({
  type: z.literal('SVCB'),
  priority: z.number().int().min(0).max(65535),
  target: z.string(),
  svc_params: z.string()
});

const RecordPTRSchema = z.object({
  type: z.literal('PTR'),
  target: z.string()
});

const RecordNSSchema = z.object({
  type: z.literal('NS'),
  target: z.string()
});

const RecordSOASchema = z.object({
  type: z.literal('SOA'),
  mname: z.string(),
  rname: z.string(),
  serial: z.number().int().min(0).max(4294967295),
  refresh: z.number().int(),
  retry: z.number().int(),
  expire: z.number().int(),
  minimum: z.number().int().min(0).max(4294967295)
});

const RecordCAASchema = z.object({
  type: z.literal('CAA'),
  flags: z.number().int().min(0).max(255),
  tag: z.string(),
  value: z.string()
});

const RecordTLSASchema = z.object({
  type: z.literal('TLSA'),
  usage: z.number().int().min(0).max(3),
  selector: z.number().int().min(0).max(1),
  matching_type: z.number().int().min(0).max(2),
  cert_data: z.string()
});

const RecordSMIMEASchema = z.object({
  type: z.literal('SMIMEA'),
  usage: z.number().int().min(0).max(3),
  selector: z.number().int().min(0).max(1),
  matching_type: z.number().int().min(0).max(2),
  cert_data: z.string()
});

const RecordSSHFPSchema = z.object({
  type: z.literal('SSHFP'),
  algorithm: z.number().int().min(1).max(6),
  fp_type: z.number().int().min(1).max(2),
  fingerprint: z.string()
});

const RecordNAPTRSchema = z.object({
  type: z.literal('NAPTR'),
  order: z.number().int().min(0).max(65535),
  preference: z.number().int().min(0).max(65535),
  flags: z.string(),
  service: z.string(),
  regexp: z.string(),
  replacement: z.string()
});

const RecordURISchema = z.object({
  type: z.literal('URI'),
  priority: z.number().int().min(0).max(65535),
  weight: z.number().int().min(0).max(65535),
  target: z.string()
});

const RecordLOCSchema = z.object({
  type: z.literal('LOC'),
  coordinates: z.string()
});

const RecordHINFOSchema = z.object({
  type: z.literal('HINFO'),
  cpu: z.string(),
  os: z.string()
});

const RecordRPSchema = z.object({
  type: z.literal('RP'),
  mbox: z.string(),
  txt: z.string()
});

const RecordDNAMESchema = z.object({
  type: z.literal('DNAME'),
  target: z.string()
});

const RecordDSSchema = z.object({
  type: z.literal('DS'),
  key_tag: z.number().int().min(0).max(65535),
  algorithm: z.number().int().min(1).max(255),
  digest_type: z.number().int().min(1).max(4),
  digest: z.string()
});

const RecordDNSKEYSchema = z.object({
  type: z.literal('DNSKEY'),
  flags: z.number().int().min(0).max(65535),
  protocol: z.number().int().min(0).max(255),
  algorithm: z.number().int().min(1).max(255),
  public_key: z.string()
});

const RecordOPENPGPKEYSchema = z.object({
  type: z.literal('OPENPGPKEY'),
  public_key: z.string()
});

const RecordCERTSchema = z.object({
  type: z.literal('CERT'),
  cert_type: z.number().int().min(0).max(65535),
  key_tag: z.number().int().min(0).max(65535),
  algorithm: z.number().int().min(0).max(255),
  cert_data: z.string()
});

const RecordCSYNCSchema = z.object({
  type: z.literal('CSYNC'),
  soa_serial: z.number().int().min(0).max(4294967295),
  flags: z.number().int().min(0).max(65535),
  types: z.string()
});

const RecordRAWSchema = z.object({
  type: z.literal('RAW'),
  rr_type: z.number().int().min(1).max(65535),
  rdata_hex: z.string()
});

export const LocalRecordDataSchema = z.discriminatedUnion('type', [
  RecordASchema,
  RecordAAAASchema,
  RecordCNAMESchema,
  RecordANAMESchema,
  RecordMXSchema,
  RecordTXTSchema,
  RecordSPFSchema,
  RecordSRVSchema,
  RecordHTTPSSchema,
  RecordSVCBSchema,
  RecordPTRSchema,
  RecordNSSchema,
  RecordSOASchema,
  RecordCAASchema,
  RecordTLSASchema,
  RecordSMIMEASchema,
  RecordSSHFPSchema,
  RecordNAPTRSchema,
  RecordURISchema,
  RecordLOCSchema,
  RecordHINFOSchema,
  RecordRPSchema,
  RecordDNAMESchema,
  RecordDSSchema,
  RecordDNSKEYSchema,
  RecordOPENPGPKEYSchema,
  RecordCERTSchema,
  RecordCSYNCSchema,
  RecordRAWSchema
]);
export type LocalRecordData = z.infer<typeof LocalRecordDataSchema>;

export const LocalDnsRecordViewSchema = z.object({
  id: RecordIdSchema,
  zone_id: z.string().nullable().optional(),
  zone_name: z.string().nullable().optional(),
  domain: z.string().min(1).max(255),
  ttl: z.number().int().min(1).max(604800),
  enabled: z.boolean(),
  comment: z.string(),
  updated_at: z.string(),
  updated_at_epoch: z.number().int().nonnegative(),
  record: LocalRecordDataSchema,
  rr_type_code: z.number().int().min(1).max(65535),
  bind_preview: z.string()
});
export type LocalDnsRecordView = z.infer<typeof LocalDnsRecordViewSchema>;

export const PaginatedLocalDnsRecordsSchema = createPaginatedSchema(LocalDnsRecordViewSchema);

export const RecordPreviewResponseSchema = z.object({
  canonical_domain: z.string(),
  rr_type_code: z.number().int().min(1).max(65535),
  bind_line: z.string(),
  wire_size_bytes: z.number().int().nonnegative(),
  auto_ptr_preview: z.string().nullable()
});
export type RecordPreviewResponse = z.infer<typeof RecordPreviewResponseSchema>;

export const BulkImportRecordsResponseSchema = z.object({
  imported_count: z.number().int().nonnegative(),
  skipped_count: z.number().int().nonnegative(),
  errors: z.array(z.string())
});
export type BulkImportRecordsResponse = z.infer<typeof BulkImportRecordsResponseSchema>;

export interface UpsertRecordPayload {
  zone_id?: string | null;
  domain: string;
  ttl: number;
  enabled: boolean;
  comment: string;
  record: LocalRecordData;
}

export interface LocalDnsRecordsFeatureProps {
  readonly role: AdminRole;
}

export interface CloudflareRecordModalProps {
  readonly isOpen: boolean;
  readonly editRecord: LocalDnsRecordView | null;
  readonly isCloneMode?: boolean;
  readonly activeZone: DnsZoneView | null;
  readonly existingRecords: readonly LocalDnsRecordView[];
  readonly onClose: () => void;
  readonly onSubmitRecord: (payload: UpsertRecordPayload, existingId?: RecordId) => Promise<void>;
}
