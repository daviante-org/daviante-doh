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

export function useDnsLookup() {
  const [result, setResult] = useState<DnsLookupResponse | null>(null);
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
      setResult(res);
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
    lookupError,
    isRunning,
    onSubmit
  };
}
