import { useEffect, useState } from 'react';
import { useDebounce } from '../../../hooks';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import type { AdminRole, RuleId } from '../../../types';
import { policyService } from '../services/policyService';
import {
  type AddRuleFormValues,
  type DnsRuleView,
  type PolicyAction,
  type PolicyMatchMode,
  type PolicySettingsView,
  validateSinkholeSettings
} from '../types/policy.types';

export type RuleMatchModeFilter = 'ALL' | PolicyMatchMode;
export type RuleActionFilter = 'ALL' | PolicyAction;

export function useProtectivePolicy(role: AdminRole) {
  const isReadOnly = role === 'ReadOnly';

  const [settings, setSettings] = useState<PolicySettingsView | null>(null);
  const [rules, setRules] = useState<DnsRuleView[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 250);

  const [matchModeFilter, setMatchModeFilter] = useState<RuleMatchModeFilter>('ALL');
  const [actionFilter, setActionFilter] = useState<RuleActionFilter>('ALL');

  const [isLoading, setIsLoading] = useState(true);
  const [pageError, setPageError] = useState<string | null>(null);
  const [settingsSuccess, setSettingsSuccess] = useState<string | null>(null);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [isAddRuleModalOpen, setIsAddRuleModalOpen] = useState(false);

  const filteredRules = rules.filter((r) => {
    if (matchModeFilter !== 'ALL' && r.match_mode !== matchModeFilter) {
      return false;
    }
    if (actionFilter !== 'ALL' && r.action !== actionFilter) {
      return false;
    }
    return true;
  });

  const selectedRule =
    filteredRules.find((r) => r.id === selectedRuleId) ?? filteredRules[0] ?? null;

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
      if (rulesRes.items.length > 0) {
        setSelectedRuleId((prev) => {
          if (prev !== null && rulesRes.items.some((r) => r.id === prev)) {
            return prev;
          }
          return rulesRes.items[0]?.id ?? null;
        });
      } else {
        setSelectedRuleId(null);
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
    void loadData();
  }, [page, perPage, debouncedSearch]);

  const handleClearRuleFilters = (): void => {
    setSearchInput('');
    setMatchModeFilter('ALL');
    setActionFilter('ALL');
    setPage(1);
  };

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
    const created = await policyService.createRule({
      pattern: values.pattern.trim().toLowerCase(),
      match_mode: values.match_mode,
      action: values.action,
      comment: values.comment.trim()
    });
    setSelectedRuleId(created.id);
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
    filteredRules,
    selectedRule,
    selectedRuleId,
    total,
    page,
    perPage,
    searchInput,
    matchModeFilter,
    actionFilter,
    isLoading,
    pageError,
    settingsSuccess,
    isSavingSettings,
    isAddRuleModalOpen,
    setSelectedRuleId,
    setPage,
    setPerPage,
    setSearchInput,
    setMatchModeFilter,
    setActionFilter,
    setIsAddRuleModalOpen,
    loadData,
    handleClearRuleFilters,
    handleUpdateSettingsField,
    handleSaveSettings,
    handleAddRule,
    handleDeleteRule
  };
}
