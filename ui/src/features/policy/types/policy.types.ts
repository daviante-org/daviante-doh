import { z } from 'zod';
import { type AdminRole, createPaginatedSchema, type RuleId, RuleIdSchema } from '../../../types';
import { isValidDnsDomain, isValidIpv4, isValidIpv6 } from '../../../utils';

export const PolicyMatchModeSchema = z.enum(['Exact', 'Suffix']);
export type PolicyMatchMode = z.infer<typeof PolicyMatchModeSchema>;

export const PolicyActionSchema = z.enum(['Allow', 'BlockNxDomain', 'Sinkhole']);
export type PolicyAction = z.infer<typeof PolicyActionSchema>;

export const DnsRuleViewSchema = z.object({
  id: RuleIdSchema,
  pattern: z.string().min(1).max(255),
  match_mode: PolicyMatchModeSchema,
  action: PolicyActionSchema,
  comment: z.string(),
  updated_at_epoch: z.number().int().nonnegative()
});
export type DnsRuleView = z.infer<typeof DnsRuleViewSchema>;

export const PaginatedDnsRulesSchema = createPaginatedSchema(DnsRuleViewSchema);

export const PolicySettingsViewSchema = z.object({
  enabled: z.boolean(),
  sinkhole_ipv4: z.string(),
  sinkhole_ipv6: z.string(),
  block_private_rebinding: z.boolean()
});
export type PolicySettingsView = z.infer<typeof PolicySettingsViewSchema>;

export const AddRuleFormSchema = z.object({
  pattern: z
    .string()
    .trim()
    .min(1, 'Domain pattern is required.')
    .max(253, 'Domain pattern must not exceed 253 characters.')
    .refine((val) => isValidDnsDomain(val, false), {
      message: 'Enter a valid domain name (e.g., ads.example.com or telemetry.corp.internal).'
    }),
  match_mode: PolicyMatchModeSchema,
  action: PolicyActionSchema,
  comment: z.string().max(256, 'Comment must not exceed 256 characters.')
});
export type AddRuleFormValues = z.infer<typeof AddRuleFormSchema>;

export function validateSinkholeSettings(ipv4: string, ipv6: string): string | null {
  if (!isValidIpv4(ipv4.trim())) {
    return 'Sinkhole IPv4 must be a valid dotted-quad IPv4 address (e.g., 0.0.0.0).';
  }
  if (!isValidIpv6(ipv6.trim())) {
    return 'Sinkhole IPv6 must be a valid IPv6 address (e.g., ::).';
  }
  return null;
}

export interface ProtectivePolicyFeatureProps {
  readonly role: AdminRole;
}

export interface PolicyEnforcementCardProps {
  readonly settings: PolicySettingsView | null;
  readonly isReadOnly: boolean;
  readonly isSavingSettings: boolean;
  readonly onUpdateSettingsField: <K extends keyof PolicySettingsView>(
    field: K,
    value: PolicySettingsView[K]
  ) => void;
  readonly onSaveSettings: () => Promise<void>;
}

export interface PolicyRulesTableCardProps {
  readonly rules: readonly DnsRuleView[];
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
  readonly searchInput: string;
  readonly isLoading: boolean;
  readonly isReadOnly: boolean;
  readonly onSearchChange: (val: string) => void;
  readonly onPageChange: (page: number) => void;
  readonly onPerPageChange: (perPage: number) => void;
  readonly onOpenAddModal: () => void;
  readonly onDeleteRule: (ruleId: RuleId) => Promise<void>;
}

export interface AddPolicyRuleModalProps {
  readonly isOpen: boolean;
  readonly onClose: () => void;
  readonly onSubmitRule: (values: AddRuleFormValues) => Promise<void>;
}
