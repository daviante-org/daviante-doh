import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import type { DnsRecordType } from '../../../constants';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import type { RecordId } from '../../../types';
import { resolveOwnerInZone } from '../../../utils';
import { dnsRecordsService } from '../services/dnsRecordsService';
import type {
  DnsZoneView,
  LocalDnsRecordView,
  LocalRecordData,
  RecordPreviewResponse,
  UpsertRecordPayload
} from '../types/dnsRecords.types';
import {
  defaultRecordDataForType,
  formatLiveBindPreview,
  UpsertRecordFormSchema,
  type UpsertRecordFormValues,
  validateRecordAgainstExisting
} from '../utils/recordValidation';

export function useRecordFormModal(params: {
  readonly isOpen: boolean;
  readonly editRecord: LocalDnsRecordView | null;
  readonly isCloneMode: boolean;
  readonly activeZone: DnsZoneView | null;
  readonly existingRecords: readonly LocalDnsRecordView[];
  readonly onClose: () => void;
  readonly onSubmitRecord: (payload: UpsertRecordPayload, existingId?: RecordId) => Promise<void>;
}) {
  const {
    isOpen,
    editRecord,
    isCloneMode,
    activeZone,
    existingRecords,
    onClose,
    onSubmitRecord
  } = params;

  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverPreview, setServerPreview] = useState<RecordPreviewResponse | null>(null);

  const form = useForm<UpsertRecordFormValues>({
    resolver: zodResolver(UpsertRecordFormSchema),
    defaultValues: {
      domain: activeZone ? '@' : 'app.internal.corp',
      ttl: activeZone?.default_ttl ?? 300,
      enabled: true,
      comment: '',
      record: defaultRecordDataForType('A')
    }
  });

  const { reset, watch, setValue } = form;

  useEffect(() => {
    if (isOpen) {
      setSubmitError(null);
      setServerPreview(null);
      if (editRecord !== null) {
        const clonedDomain = isCloneMode ? `copy-${editRecord.domain}` : editRecord.domain;
        reset({
          domain: clonedDomain,
          ttl: editRecord.ttl,
          enabled: editRecord.enabled,
          comment: editRecord.comment,
          record: editRecord.record
        });
      } else {
        reset({
          domain: activeZone ? '@' : 'app.internal.corp',
          ttl: activeZone?.default_ttl ?? 300,
          enabled: true,
          comment: '',
          record: defaultRecordDataForType('A')
        });
      }
    }
  }, [isOpen, editRecord, isCloneMode, activeZone, reset]);

  const watchedDomain = watch('domain');
  const watchedTtl = watch('ttl');
  const watchedEnabled = watch('enabled');
  const watchedComment = watch('comment');
  const watchedRecord = watch('record');

  const resolvedDomainPreview =
    watchedRecord.type === 'PTR' &&
    (watchedDomain.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(watchedDomain.trim()))
      ? watchedDomain.trim()
      : resolveOwnerInZone(watchedDomain, activeZone?.name);

  const liveBindLine = formatLiveBindPreview(resolvedDomainPreview, watchedTtl, watchedRecord);

  useEffect(() => {
    if (!isOpen || !watchedDomain.trim()) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      void dnsRecordsService
        .previewRecord({
          zone_id: activeZone?.id ?? editRecord?.zone_id ?? null,
          domain: watchedDomain.trim(),
          ttl: watchedTtl,
          enabled: watchedEnabled,
          comment: watchedComment,
          record: watchedRecord
        })
        .then((res) => { setServerPreview(res); })
        .catch(() => { setServerPreview(null); });
    }, 300);

    return () => { window.clearTimeout(timer); };
  }, [
    isOpen,
    activeZone?.id,
    editRecord?.zone_id,
    watchedDomain,
    watchedTtl,
    watchedEnabled,
    watchedComment,
    watchedRecord
  ]);

  const handleRecordTypeChange = (nextType: DnsRecordType): void => {
    setSubmitError(null);
    setValue('record', defaultRecordDataForType(nextType), { shouldValidate: true });
  };

  const updateRecordField = <T extends LocalRecordData>(updater: (current: T) => T): void => {
    setValue('record', updater(watchedRecord as T), { shouldValidate: true });
  };

  const onFormSubmit = async (values: UpsertRecordFormValues): Promise<void> => {
    setSubmitError(null);

    const resolvedDomain =
      values.record.type === 'PTR' &&
      (values.domain.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(values.domain.trim()))
        ? values.domain.trim()
        : resolveOwnerInZone(values.domain, activeZone?.name);

    const effectiveEditId = isCloneMode ? undefined : editRecord?.id;
    const conflictError = validateRecordAgainstExisting(
      resolvedDomain,
      values.record,
      existingRecords,
      effectiveEditId
    );
    if (conflictError !== null) {
      setSubmitError(conflictError);
      return;
    }

    setIsSubmitting(true);
    try {
      await onSubmitRecord(
        {
          zone_id: activeZone?.id ?? editRecord?.zone_id ?? null,
          domain: values.domain.trim(),
          ttl: values.ttl,
          enabled: values.enabled,
          comment: values.comment.trim(),
          record: values.record
        },
        effectiveEditId
      );
      onClose();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setSubmitError(err.userMessage);
      } else {
        setSubmitError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return {
    form,
    submitError,
    isSubmitting,
    serverPreview,
    watchedDomain,
    watchedTtl,
    watchedRecord,
    resolvedDomainPreview,
    liveBindLine,
    handleRecordTypeChange,
    updateRecordField,
    onFormSubmit
  };
}
