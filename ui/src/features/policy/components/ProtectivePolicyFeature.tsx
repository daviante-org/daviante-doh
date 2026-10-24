import React from 'react';
import {
  Alert,
  Button,
  Content,
  Flex,
  FlexItem,
  Grid,
  GridItem,
  PageSection,
  Stack,
  StackItem,
  Title
} from '@patternfly/react-core';
import { SyncAltIcon } from '@patternfly/react-icons';
import { useProtectivePolicy } from '../hooks/useProtectivePolicy';
import type { ProtectivePolicyFeatureProps } from '../types/policy.types';
import { AddPolicyRuleModal } from './AddPolicyRuleModal';
import { PolicyRuleDetailCard } from './PolicyRuleDetailCard';
import { PolicyRuleDirectoryCard } from './PolicyRuleDirectoryCard';

export function ProtectivePolicyFeature({
  role
}: ProtectivePolicyFeatureProps): React.JSX.Element {
  const {
    isReadOnly,
    settings,
    filteredRules,
    selectedRule,
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
  } = useProtectivePolicy(role);

  return (
    <>
      <PageSection>
        <Stack hasGutter>
          <StackItem>
            <Flex
              justifyContent={{ default: 'justifyContentSpaceBetween' }}
              alignItems={{ default: 'alignItemsFlexStart' }}
              gap={{ default: 'gapMd' }}
            >
              <FlexItem>
                <Title headingLevel="h1" size="2xl">
                  Protective DNS &amp; Filtering Policy
                </Title>
                <Content component="p">
                  Configure threat-blocking rules (NXDOMAIN or Sinkhole), explicit allowlist
                  overrides, and DNS Rebinding protection against private RFC 1918 upstream
                  responses.
                </Content>
              </FlexItem>
              <FlexItem>
                <Button
                  variant="secondary"
                  icon={<SyncAltIcon />}
                  isLoading={isLoading}
                  onClick={() => {
                    void loadData();
                  }}
                >
                  Refresh
                </Button>
              </FlexItem>
            </Flex>
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
        </Stack>
      </PageSection>

      <PageSection isFilled>
        <Grid hasGutter>
          <GridItem span={12} lg={4}>
            <PolicyRuleDirectoryCard
              rules={filteredRules}
              selectedRule={selectedRule}
              total={total}
              page={page}
              perPage={perPage}
              searchInput={searchInput}
              matchModeFilter={matchModeFilter}
              actionFilter={actionFilter}
              isLoading={isLoading}
              isReadOnly={isReadOnly}
              onSelectRule={setSelectedRuleId}
              onSearchChange={setSearchInput}
              onMatchModeFilterChange={setMatchModeFilter}
              onActionFilterChange={setActionFilter}
              onClearFilters={handleClearRuleFilters}
              onPageChange={setPage}
              onPerPageChange={setPerPage}
              onOpenAddModal={() => {
                setIsAddRuleModalOpen(true);
              }}
            />
          </GridItem>

          <GridItem span={12} lg={8}>
            <PolicyRuleDetailCard
              selectedRule={selectedRule}
              settings={settings}
              isReadOnly={isReadOnly}
              isSavingSettings={isSavingSettings}
              onUpdateSettingsField={handleUpdateSettingsField}
              onSaveSettings={handleSaveSettings}
              onDeleteRule={handleDeleteRule}
            />
          </GridItem>
        </Grid>
      </PageSection>

      <AddPolicyRuleModal
        isOpen={isAddRuleModalOpen}
        onClose={() => {
          setIsAddRuleModalOpen(false);
        }}
        onSubmitRule={handleAddRule}
      />
    </>
  );
}
