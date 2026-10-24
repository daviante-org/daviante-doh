import { z } from 'zod';
import { httpClient } from '../../../services';
import type { PaginatedList, RuleId } from '../../../types';
import {
  type DnsRuleView,
  DnsRuleViewSchema,
  PaginatedDnsRulesSchema,
  type PolicyAction,
  type PolicyMatchMode,
  type PolicySettingsView,
  PolicySettingsViewSchema
} from '../types/policy.types';

export const policyService = {
  async getPolicySettings(): Promise<PolicySettingsView> {
    return httpClient.request('/api/v1/policy/settings', { method: 'GET' }, PolicySettingsViewSchema);
  },

  async updatePolicySettings(payload: PolicySettingsView): Promise<PolicySettingsView> {
    return httpClient.request(
      '/api/v1/policy/settings',
      {
        method: 'PUT',
        body: JSON.stringify(payload)
      },
      PolicySettingsViewSchema
    );
  },

  async listRules(
    page = 1,
    perPage = 20,
    search = ''
  ): Promise<PaginatedList<DnsRuleView>> {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(Math.min(perPage, 100))
    });
    if (search.trim().length > 0) {
      params.set('search', search.trim());
    }
    return httpClient.request(
      `/api/v1/policy/rules?${params.toString()}`,
      { method: 'GET' },
      PaginatedDnsRulesSchema
    );
  },

  async createRule(payload: {
    pattern: string;
    match_mode: PolicyMatchMode;
    action: PolicyAction;
    comment: string;
  }): Promise<DnsRuleView> {
    return httpClient.request(
      '/api/v1/policy/rules',
      {
        method: 'POST',
        body: JSON.stringify(payload)
      },
      DnsRuleViewSchema
    );
  },

  async deleteRule(id: RuleId): Promise<void> {
    await httpClient.request(
      `/api/v1/policy/rules/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
      z.object({ deleted: z.boolean() })
    );
  }
};
