import { useEffect, useState } from 'react';
import { useDebounce } from '../../../hooks';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import type { AdminRole, RuleId } from '../../../types';
import { policyService } from '../services/policyService';
import {
  type AddRuleFormValues,
  type DnsRuleView,
  type PolicySettingsView,
  validateSinkholeSettings
} from '../types/policy.types';

export function useProtectivePolicy(role: AdminRole) {
  const isReadOnly = role === 'ReadOnly';

  const [settings, setSettings] = useState<PolicySettingsView | null>(null);
  const [rules, setRules] = useState<DnsRuleView[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 250);

  const [isLoading, setIsLoading] = useState(true);
  const [pageError, setPageError] = useState<string | null>(null);
  const [settingsSuccess, setSettingsSuccess] = useState<string | null>(null);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [isAddRuleModalOpen, setIsAddRuleModalOpen] = useState(false);

  const loadData = async (): Promise<void> => {
    setIsLoading(true);
    setPageError(null);
    try {
      const [settingsRes, rulesRes] = await Promise.all([
        policyService.getPolicySettings(),
        policyService.listRules(page, perPage, debouncedSearch)
      ]);
      setSettings(settingsRes);
      setRules(rulesRes.items);
      setTotal(rulesRes.total);
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
    void loadData();
  }, [page, perPage, debouncedSearch]);

  const handleUpdateSettingsField = <K extends keyof PolicySettingsView>(
    field: K,
    value: PolicySettingsView[K]
  ): void => {
    setSettings((prev) => (prev ? { ...prev, [field]: value } : prev));
  };

  const handleSaveSettings = async (): Promise<void> => {
    if (!settings) {
      return;
    }
    setPageError(null);
    setSettingsSuccess(null);

    const validationError = validateSinkholeSettings(
      settings.sinkhole_ipv4,
      settings.sinkhole_ipv6
    );
    if (validationError) {
      setPageError(validationError);
      return;
    }

    setIsSavingSettings(true);
    try {
      const updated = await policyService.updatePolicySettings({
        enabled: settings.enabled,
        sinkhole_ipv4: settings.sinkhole_ipv4.trim(),
        sinkhole_ipv6: settings.sinkhole_ipv6.trim(),
        block_private_rebinding: settings.block_private_rebinding
      });
      setSettings(updated);
      setSettingsSuccess('Protective DNS policy settings saved.');
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsSavingSettings(false);
    }
  };

  const handleAddRule = async (values: AddRuleFormValues): Promise<void> => {
    await policyService.createRule({
      pattern: values.pattern.trim().toLowerCase(),
      match_mode: values.match_mode,
      action: values.action,
      comment: values.comment.trim()
    });
    setIsAddRuleModalOpen(false);
    await loadData();
  };

  const handleDeleteRule = async (ruleId: RuleId): Promise<void> => {
    setPageError(null);
    try {
      await policyService.deleteRule(ruleId);
      await loadData();
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setPageError(err.userMessage);
      } else {
        setPageError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    }
  };

  return {
    isReadOnly,
    settings,
    rules,
    total,
    page,
    perPage,
    searchInput,
    isLoading,
    pageError,
    settingsSuccess,
    isSavingSettings,
    isAddRuleModalOpen,
    setPage,
    setPerPage,
    setSearchInput,
    setIsAddRuleModalOpen,
    handleUpdateSettingsField,
    handleSaveSettings,
    handleAddRule,
    handleDeleteRule
  };
}
