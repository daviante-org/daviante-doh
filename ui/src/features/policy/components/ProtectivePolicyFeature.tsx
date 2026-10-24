import React from 'react';
import {
  Alert,
  Content,
  ContentVariants,
  PageSection,
  Stack,
  StackItem
} from '@patternfly/react-core';
import { useProtectivePolicy } from '../hooks/useProtectivePolicy';
import type { ProtectivePolicyFeatureProps } from '../types/policy.types';
import { AddPolicyRuleModal } from './AddPolicyRuleModal';
import { PolicyEnforcementCard } from './PolicyEnforcementCard';
import { PolicyRulesTableCard } from './PolicyRulesTableCard';

export function ProtectivePolicyFeature({
  role
}: ProtectivePolicyFeatureProps): React.JSX.Element {
  const {
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
  } = useProtectivePolicy(role);

  return (
    <PageSection isFilled>
      <Stack hasGutter>
        <StackItem>
          <Content component={ContentVariants.h1}>Protective DNS &amp; Filtering Policy</Content>
          <Content component={ContentVariants.p}>
            Configure threat-blocking rules (NXDOMAIN or Sinkhole), explicit allowlist overrides, and
            DNS Rebinding protection against private RFC 1918 upstream responses.
          </Content>
        </StackItem>

        {pageError !== null && (
          <StackItem>
            <Alert variant="danger" isInline title={pageError} />
          </StackItem>
        )}

        {settingsSuccess !== null && (
          <StackItem>
            <Alert variant="success" isInline title={settingsSuccess} />
          </StackItem>
        )}

        <StackItem>
          <PolicyEnforcementCard
            settings={settings}
            isReadOnly={isReadOnly}
            isSavingSettings={isSavingSettings}
            onUpdateSettingsField={handleUpdateSettingsField}
            onSaveSettings={handleSaveSettings}
          />
        </StackItem>

        <StackItem>
          <PolicyRulesTableCard
            rules={rules}
            total={total}
            page={page}
            perPage={perPage}
            searchInput={searchInput}
            isLoading={isLoading}
            isReadOnly={isReadOnly}
            onSearchChange={setSearchInput}
            onPageChange={setPage}
            onPerPageChange={setPerPage}
            onOpenAddModal={() => { setIsAddRuleModalOpen(true); }}
            onDeleteRule={handleDeleteRule}
          />
        </StackItem>
      </Stack>

      <AddPolicyRuleModal
        isOpen={isAddRuleModalOpen}
        onClose={() => { setIsAddRuleModalOpen(false); }}
        onSubmitRule={handleAddRule}
      />
    </PageSection>
  );
}
