import { useEffect, useState } from 'react';
import type { DnsRecordType, RecordCategoryFilter } from '../../../constants';
import { useDebounce } from '../../../hooks';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import type { AdminRole, RecordId } from '../../../types';
import { isValidDnsDomain, parseIntClamped } from '../../../utils';
import { dnsRecordsService } from '../services/dnsRecordsService';
import type {
  BulkImportRecordsResponse,
  DnsZoneView,
  LocalDnsRecordView,
  UpsertRecordPayload,
  ZoneMode
} from '../types/dnsRecords.types';
import { matchesCategoryFilter } from '../utils/recordFormatters';

export type DnsDirectoryMode = 'records' | 'zones';

export interface ZoneFormState {
  name: string;
  mode: ZoneMode;
  primaryNs: string;
  adminEmail: string;
  refresh: string;
  retry: string;
  expire: string;
  minimum: string;
  defaultTtl: string;
  enabled: boolean;
  comment: string;
}

export function useDnsRecordsWorkspace(role: AdminRole) {
  const isReadOnly = role === 'ReadOnly';

  const [directoryMode, setDirectoryMode] = useState<DnsDirectoryMode>('records');
  const [zones, setZones] = useState<DnsZoneView[]>([]);
  const [selectedZoneKey, setSelectedZoneKey] = useState<string>('ALL');
  const [zoneSearchInput, setZoneSearchInput] = useState('');

  const [records, setRecords] = useState<LocalDnsRecordView[]>([]);
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 250);

  const [filterRecordType, setFilterRecordType] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<RecordCategoryFilter>('ALL');
  const [filterEnabled, setFilterEnabled] = useState<'all' | 'enabled' | 'disabled'>('all');

  const [expandedRecordIds, setExpandedRecordIds] = useState<Set<string>>(new Set());
  const [selectedRecordIds, setSelectedRecordIds] = useState<Set<string>>(new Set());

  const [isLoading, setIsLoading] = useState(true);
  const [pageError, setPageError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const [isRecordModalOpen, setIsRecordModalOpen] = useState(false);
  const [editingRecord, setEditingRecord] = useState<LocalDnsRecordView | null>(null);
  const [isCloningRecord, setIsCloningRecord] = useState(false);

  const [deletingRecord, setDeletingRecord] = useState<LocalDnsRecordView | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  const [isZoneModalOpen, setIsZoneModalOpen] = useState(false);
  const [editingZone, setEditingZone] = useState<DnsZoneView | null>(null);
  const [zoneForm, setZoneForm] = useState<ZoneFormState>({
    name: '',
    mode: 'authoritative',
    primaryNs: 'ns1.internal.corp',
    adminEmail: 'hostmaster.internal.corp',
    refresh: '3600',
    retry: '600',
    expire: '86400',
    minimum: '300',
    defaultTtl: '300',
    enabled: true,
    comment: ''
  });
  const [zoneFormError, setZoneFormError] = useState<string | null>(null);
  const [isSavingZone, setIsSavingZone] = useState(false);

  const [deletingZone, setDeletingZone] = useState<DnsZoneView | null>(null);
  const [deleteZoneCascade, setDeleteZoneCascade] = useState(false);
  const [isDeletingZone, setIsDeletingZone] = useState(false);

  const [exportBindOutput, setExportBindOutput] = useState<{
    zoneName: string;
    content: string;
  } | null>(null);

  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importFormat, setImportFormat] = useState<'bind' | 'json'>('bind');
  const [importText, setImportText] = useState('');
  const [importDefaultTtl, setImportDefaultTtl] = useState('300');
  const [isImporting, setIsImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<BulkImportRecordsResponse | null>(null);

  const activeZone =
    selectedZoneKey !== 'ALL' && selectedZoneKey !== 'UNZONED'
      ? (zones.find((z) => z.id === selectedZoneKey) ?? null)
      : null;

  const filteredZones = zones.filter((z) => {
    const q = zoneSearchInput.trim().toLowerCase();
    if (!q) return true;
    return z.name.toLowerCase().includes(q) || z.comment.toLowerCase().includes(q);
  });

  const visibleRecords = records.filter((item) =>
    matchesCategoryFilter(item.record.type, categoryFilter)
  );

  const selectedRecord =
    visibleRecords.find((r) => r.id === selectedRecordId) ?? visibleRecords[0] ?? null;

  const selectedZone =
    activeZone ?? filteredZones[0] ?? zones[0] ?? null;

  const loadZonesAndRecords = async (): Promise<void> => {
    setIsLoading(true);
    setPageError(null);
    try {
      const zoneFilterParam = selectedZoneKey === 'ALL' ? '' : selectedZoneKey;
      const [zonesRes, recordsRes] = await Promise.all([
        dnsRecordsService.listZones(),
        dnsRecordsService.listRecords(
          page,
          perPage,
          debouncedSearch,
          filterRecordType,
          filterEnabled,
          zoneFilterParam
        )
      ]);
      setZones(zonesRes);
      setRecords(recordsRes.items);
      setTotal(recordsRes.total);
      setSelectedRecordIds(new Set());
      if (recordsRes.items.length > 0) {
        setSelectedRecordId((prev) => {
          if (prev !== null && recordsRes.items.some((r) => r.id === prev)) {
            return prev;
          }
          return recordsRes.items[0]?.id ?? null;
        });
      } else {
        setSelectedRecordId(null);
      }
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadZonesAndRecords();
  }, [page, perPage, debouncedSearch, filterRecordType, filterEnabled, selectedZoneKey]);

  const handleClearRecordFilters = (): void => {
    setSearchInput('');
    setSelectedZoneKey('ALL');
    setFilterRecordType('');
    setCategoryFilter('ALL');
    setFilterEnabled('all');
    setPage(1);
  };

  const openCreateRecordModal = (): void => {
    setEditingRecord(null);
    setIsCloningRecord(false);
    setIsRecordModalOpen(true);
  };

  const openEditRecordModal = (record: LocalDnsRecordView): void => {
    setEditingRecord(record);
    setIsCloningRecord(false);
    setIsRecordModalOpen(true);
  };

  const openCloneRecordModal = (record: LocalDnsRecordView): void => {
    setEditingRecord(record);
    setIsCloningRecord(true);
    setIsRecordModalOpen(true);
  };

  const handleSubmitRecord = async (
    payload: UpsertRecordPayload,
    existingId?: RecordId
  ): Promise<void> => {
    setActionSuccess(null);
    if (existingId !== undefined) {
      await dnsRecordsService.updateRecord(existingId, payload);
      setActionSuccess(`Updated ${payload.record.type} record for ${payload.domain}.`);
    } else {
      const created = await dnsRecordsService.createRecord(payload);
      setSelectedRecordId(created.id);
      setActionSuccess(`Created ${payload.record.type} record for ${payload.domain}.`);
    }
    await loadZonesAndRecords();
  };

  const handleQuickToggleRecordEnabled = async (item: LocalDnsRecordView): Promise<void> => {
    setPageError(null);
    setActionSuccess(null);
    try {
      await dnsRecordsService.updateRecord(item.id, {
        zone_id: item.zone_id ?? null,
        domain: item.domain,
        ttl: item.ttl,
        enabled: !item.enabled,
        comment: item.comment,
        record: item.record
      });
      await loadZonesAndRecords();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    }
  };

  const handleConfirmDeleteRecord = async (): Promise<void> => {
    if (deletingRecord === null) {
      return;
    }
    setIsDeleting(true);
    setPageError(null);
    setActionSuccess(null);
    try {
      await dnsRecordsService.deleteRecord(deletingRecord.id);
      setActionSuccess(`Deleted ${deletingRecord.record.type} record for ${deletingRecord.domain}.`);
      setDeletingRecord(null);
      await loadZonesAndRecords();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsDeleting(false);
    }
  };

  const handleBulkDeleteSelected = async (): Promise<void> => {
    if (selectedRecordIds.size === 0) {
      return;
    }
    setPageError(null);
    setActionSuccess(null);
    setIsLoading(true);
    try {
      const ids = Array.from(selectedRecordIds);
      for (const rawId of ids) {
        const rec = records.find((r) => r.id === rawId);
        if (rec) {
          await dnsRecordsService.deleteRecord(rec.id);
        }
      }
      setActionSuccess(`Deleted ${String(ids.length)} selected DNS record(s).`);
      await loadZonesAndRecords();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
      setIsLoading(false);
    }
  };

  const openCreateZoneModal = (): void => {
    setEditingZone(null);
    setZoneForm({
      name: '',
      mode: 'authoritative',
      primaryNs: 'ns1.internal.corp',
      adminEmail: 'hostmaster.internal.corp',
      refresh: '3600',
      retry: '600',
      expire: '86400',
      minimum: '300',
      defaultTtl: '300',
      enabled: true,
      comment: ''
    });
    setZoneFormError(null);
    setIsZoneModalOpen(true);
  };

  const openEditZoneModal = (zone: DnsZoneView): void => {
    setEditingZone(zone);
    setZoneForm({
      name: zone.name,
      mode: zone.mode,
      primaryNs: zone.primary_ns,
      adminEmail: zone.admin_email,
      refresh: String(zone.refresh),
      retry: String(zone.retry),
      expire: String(zone.expire),
      minimum: String(zone.minimum),
      defaultTtl: String(zone.default_ttl),
      enabled: zone.enabled,
      comment: zone.comment
    });
    setZoneFormError(null);
    setIsZoneModalOpen(true);
  };

  const handleSaveZone = async (): Promise<void> => {
    setZoneFormError(null);
    const cleanName = zoneForm.name.trim().replace(/\.$/, '').toLowerCase();
    if (!isValidDnsDomain(cleanName, false)) {
      setZoneFormError('Enter a valid DNS Zone apex domain (e.g., internal.corp or lab.local).');
      return;
    }
    const cleanNs = zoneForm.primaryNs.trim().replace(/\.$/, '').toLowerCase();
    if (!isValidDnsDomain(cleanNs, false)) {
      setZoneFormError('Primary Nameserver (MNAME) must be a valid FQDN.');
      return;
    }
    const cleanEmail = zoneForm.adminEmail.trim().replace(/\.$/, '').replace('@', '.').toLowerCase();
    if (!isValidDnsDomain(cleanEmail, false)) {
      setZoneFormError('Responsible Mailbox (RNAME) must be a valid domain-formatted mailbox.');
      return;
    }

    const payload = {
      name: cleanName,
      mode: zoneForm.mode,
      primary_ns: cleanNs,
      admin_email: cleanEmail,
      refresh: parseIntClamped(zoneForm.refresh, 3600, 60, 604800),
      retry: parseIntClamped(zoneForm.retry, 600, 60, 604800),
      expire: parseIntClamped(zoneForm.expire, 86400, 300, 2419200),
      minimum: parseIntClamped(zoneForm.minimum, 300, 1, 86400),
      default_ttl: parseIntClamped(zoneForm.defaultTtl, 300, 1, 604800),
      enabled: zoneForm.enabled,
      comment: zoneForm.comment.trim()
    };

    setIsSavingZone(true);
    try {
      if (editingZone !== null) {
        const updated = await dnsRecordsService.updateZone(editingZone.id, payload);
        setActionSuccess(
          `Updated DNS zone '${updated.name}' (SOA serial ${String(updated.serial)}).`
        );
      } else {
        const created = await dnsRecordsService.createZone(payload);
        setSelectedZoneKey(created.id);
        setActionSuccess(
          `Created DNS zone '${created.name}' (SOA serial ${String(created.serial)}).`
        );
      }
      setIsZoneModalOpen(false);
      await loadZonesAndRecords();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setZoneFormError(err.userMessage);
      } else {
        setZoneFormError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsSavingZone(false);
    }
  };

  const handleConfirmDeleteZone = async (): Promise<void> => {
    if (deletingZone === null) {
      return;
    }
    setIsDeletingZone(true);
    setPageError(null);
    try {
      const res = await dnsRecordsService.deleteZone(deletingZone.id, deleteZoneCascade);
      setActionSuccess(
        `Deleted DNS zone '${deletingZone.name}' (${String(res.deleted_records)} child record(s) removed).`
      );
      if (selectedZoneKey === deletingZone.id) {
        setSelectedZoneKey('ALL');
      }
      setDeletingZone(null);
      await loadZonesAndRecords();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsDeletingZone(false);
    }
  };

  const handleExportZoneBind = async (zone: DnsZoneView): Promise<void> => {
    setPageError(null);
    try {
      const exported = await dnsRecordsService.exportZoneBind(zone.id);
      setExportBindOutput({
        zoneName: exported.zone_name,
        content: exported.bind_zone_file
      });
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    }
  };

  const handleBulkImportSubmit = async (): Promise<void> => {
    setImportError(null);
    setImportResult(null);
    const trimmed = importText.trim();
    if (!trimmed) {
      setImportError('Paste BIND zone file lines or a JSON records array to import.');
      return;
    }

    setIsImporting(true);
    try {
      const targetZoneId = activeZone?.id ?? null;
      if (importFormat === 'bind') {
        const res = await dnsRecordsService.bulkImportRecords({
          format: 'bind',
          zone_id: targetZoneId,
          bind_text: trimmed,
          default_ttl: parseIntClamped(importDefaultTtl, activeZone?.default_ttl ?? 300, 1, 604800)
        });
        setImportResult(res);
      } else {
        let parsedJson: unknown;
        try {
          parsedJson = JSON.parse(trimmed);
        } catch {
          setImportError('Invalid JSON syntax.');
          setIsImporting(false);
          return;
        }
        const recordsArray = Array.isArray(parsedJson)
          ? (parsedJson as UpsertRecordPayload[])
          : ((parsedJson as { records?: UpsertRecordPayload[] }).records ?? []);
        const res = await dnsRecordsService.bulkImportRecords({
          format: 'json',
          zone_id: targetZoneId,
          records: recordsArray
        });
        setImportResult(res);
      }
      await loadZonesAndRecords();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setImportError(err.userMessage);
      } else {
        setImportError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsImporting(false);
    }
  };

  const toggleExpandRecord = (id: string): void => {
    setExpandedRecordIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const toggleSelectRecord = (id: string, checked: boolean): void => {
    setSelectedRecordIds((prev) => {
      const next = new Set(prev);
      if (checked) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  };

  const toggleSelectAllPage = (checked: boolean): void => {
    if (checked) {
      setSelectedRecordIds(new Set(visibleRecords.map((r) => r.id)));
    } else {
      setSelectedRecordIds(new Set());
    }
  };

  const handleSelectRecordTypeFilter = (val: string): void => {
    setFilterRecordType(val);
    if (val) {
      setCategoryFilter('ALL');
    }
    setPage(1);
  };

  const handleSelectCategoryFilter = (cat: RecordCategoryFilter): void => {
    setCategoryFilter(cat);
    if (cat !== 'ALL') {
      setFilterRecordType('');
    }
  };

  return {
    isReadOnly,
    directoryMode,
    zones,
    filteredZones,
    selectedZoneKey,
    zoneSearchInput,
    activeZone,
    selectedZone,
    records,
    visibleRecords,
    selectedRecord,
    selectedRecordId,
    total,
    page,
    perPage,
    searchInput,
    filterRecordType,
    categoryFilter,
    filterEnabled,
    expandedRecordIds,
    selectedRecordIds,
    isLoading,
    pageError,
    actionSuccess,
    isRecordModalOpen,
    editingRecord,
    isCloningRecord,
    deletingRecord,
    isDeleting,
    isZoneModalOpen,
    editingZone,
    zoneForm,
    zoneFormError,
    isSavingZone,
    deletingZone,
    deleteZoneCascade,
    isDeletingZone,
    exportBindOutput,
    isImportModalOpen,
    importFormat,
    importText,
    importDefaultTtl,
    isImporting,
    importError,
    importResult,
    setDirectoryMode,
    setSelectedZoneKey,
    setZoneSearchInput,
    setSelectedRecordId,
    setPage,
    setPerPage,
    setSearchInput,
    setFilterEnabled,
    setIsRecordModalOpen,
    setDeletingRecord,
    setIsZoneModalOpen,
    setZoneForm,
    setDeletingZone,
    setDeleteZoneCascade,
    setExportBindOutput,
    setIsImportModalOpen,
    setImportFormat,
    setImportText,
    setImportDefaultTtl,
    setImportError,
    setImportResult,
    loadZonesAndRecords,
    handleClearRecordFilters,
    openCreateRecordModal,
    openEditRecordModal,
    openCloneRecordModal,
    handleSubmitRecord,
    handleQuickToggleRecordEnabled,
    handleConfirmDeleteRecord,
    handleBulkDeleteSelected,
    openCreateZoneModal,
    openEditZoneModal,
    handleSaveZone,
    handleConfirmDeleteZone,
    handleExportZoneBind,
    handleBulkImportSubmit,
    toggleExpandRecord,
    toggleSelectRecord,
    toggleSelectAllPage,
    handleSelectRecordTypeFilter,
    handleSelectCategoryFilter,
    defaultRecordTypeFilterOptions: undefined as DnsRecordType | undefined
  };
}
