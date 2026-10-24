import { useEffect, useState } from 'react';
import { useDebounce } from '../../../hooks';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import { telemetryService } from '../services/telemetryService';
import type {
  AuditEventEntry,
  DnsActivityEntry,
  TelemetrySummaryResponse
} from '../types/telemetry.types';

export function useTelemetryDashboard() {
  const [summary, setSummary] = useState<TelemetrySummaryResponse | null>(null);
  const [activity, setActivity] = useState<DnsActivityEntry[]>([]);
  const [activityTotal, setActivityTotal] = useState(0);
  const [activityPage, setActivityPage] = useState(1);
  const [activityPerPage, setActivityPerPage] = useState(20);
  const [activitySearch, setActivitySearch] = useState('');
  const debouncedActivitySearch = useDebounce(activitySearch, 250);

  const [auditEvents, setAuditEvents] = useState<AuditEventEntry[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditPage, setAuditPage] = useState(1);
  const [auditPerPage, setAuditPerPage] = useState(20);

  const [isLoading, setIsLoading] = useState(true);
  const [pageError, setPageError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const loadTelemetry = async (): Promise<void> => {
    setPageError(null);
    try {
      const [summaryRes, activityRes, auditRes] = await Promise.all([
        telemetryService.getTelemetrySummary(),
        telemetryService.listActivity(activityPage, activityPerPage, debouncedActivitySearch),
        telemetryService.listAuditEvents(auditPage, auditPerPage)
      ]);
      setSummary(summaryRes);
      setActivity(activityRes.items);
      setActivityTotal(activityRes.total);
      setAuditEvents(auditRes.items);
      setAuditTotal(auditRes.total);
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
    void loadTelemetry();
  }, [activityPage, activityPerPage, debouncedActivitySearch, auditPage, auditPerPage]);

  useEffect(() => {
    if (!autoRefresh) {
      return undefined;
    }
    const interval = window.setInterval(() => {
      void loadTelemetry();
    }, 5000);
    return () => {
      window.clearInterval(interval);
    };
  }, [autoRefresh, activityPage, activityPerPage, debouncedActivitySearch, auditPage, auditPerPage]);

  return {
    summary,
    activity,
    activityTotal,
    activityPage,
    activityPerPage,
    activitySearch,
    auditEvents,
    auditTotal,
    auditPage,
    auditPerPage,
    isLoading,
    pageError,
    autoRefresh,
    setActivityPage,
    setActivityPerPage,
    setActivitySearch,
    setAuditPage,
    setAuditPerPage,
    setAutoRefresh,
    loadTelemetry
  };
}
