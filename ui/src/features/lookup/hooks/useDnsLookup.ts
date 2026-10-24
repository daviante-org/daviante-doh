import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import { lookupService } from '../services/lookupService';
import {
  DnsLookupFormSchema,
  type DnsLookupFormValues,
  type DnsLookupResponse
} from '../types/lookup.types';

export interface LookupHistoryEntry {
  readonly id: string;
  readonly executedAt: string;
  readonly response: DnsLookupResponse;
}

export function useDnsLookup() {
  const [history, setHistory] = useState<LookupHistoryEntry[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const form = useForm<DnsLookupFormValues>({
    resolver: zodResolver(DnsLookupFormSchema),
    defaultValues: {
      domain: 'cloudflare.com',
      rr_type: 'A',
      dnssec_do: true,
      checking_disabled: false
    }
  });

  const selectedEntry =
    history.find((item) => item.id === selectedHistoryId) ?? history[0] ?? null;

  const result = selectedEntry?.response ?? null;

  const onSubmit = async (values: DnsLookupFormValues): Promise<void> => {
    setLookupError(null);
    setIsRunning(true);
    try {
      const res = await lookupService.runDnsLookup({
        domain: values.domain.trim(),
        rr_type: values.rr_type,
        dnssec_do: values.dnssec_do,
        checking_disabled: values.checking_disabled
      });
      const entryId = `lookup-${String(Date.now())}`;
      const newEntry: LookupHistoryEntry = {
        id: entryId,
        executedAt: new Date().toLocaleTimeString(),
        response: res
      };
      setHistory((prev) => [newEntry, ...prev.slice(0, 19)]);
      setSelectedHistoryId(entryId);
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setLookupError(err.userMessage);
      } else {
        setLookupError(mapErrorCodeToStaticMessage('UPSTREAM_LOOKUP_FAILED'));
      }
    } finally {
      setIsRunning(false);
    }
  };

  return {
    form,
    result,
    selectedEntry,
    history,
    selectedHistoryId,
    setSelectedHistoryId,
    lookupError,
    isRunning,
    onSubmit
  };
}
