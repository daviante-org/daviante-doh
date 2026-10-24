import React from 'react';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Content,
  DataList,
  DataListCell,
  DataListItem,
  DataListItemCells,
  DataListItemRow,
  Divider,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  Flex,
  FlexItem,
  FormSelect,
  FormSelectOption,
  Label,
  Pagination,
  SearchInput,
  Spinner,
  Stack,
  StackItem
} from '@patternfly/react-core';
import {
  BanIcon,
  CheckCircleIcon,
  LockIcon,
  PlusCircleIcon,
  SearchIcon,
  ShieldAltIcon
} from '@patternfly/react-icons';
import { PER_PAGE_OPTIONS } from '../../../constants';
import { assertNever } from '../../../utils';
import type { RuleActionFilter, RuleMatchModeFilter } from '../hooks/useProtectivePolicy';
import type { DnsRuleView, PolicyAction } from '../types/policy.types';

export interface PolicyRuleDirectoryCardProps {
  readonly rules: readonly DnsRuleView[];
  readonly selectedRule: DnsRuleView | null;
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
  readonly searchInput: string;
  readonly matchModeFilter: RuleMatchModeFilter;
  readonly actionFilter: RuleActionFilter;
  readonly isLoading: boolean;
  readonly isReadOnly: boolean;
  readonly onSelectRule: (ruleId: string) => void;
  readonly onSearchChange: (val: string) => void;
  readonly onMatchModeFilterChange: (mode: RuleMatchModeFilter) => void;
  readonly onActionFilterChange: (action: RuleActionFilter) => void;
  readonly onClearFilters: () => void;
  readonly onPageChange: (page: number) => void;
  readonly onPerPageChange: (perPage: number) => void;
  readonly onOpenAddModal: () => void;
}

export function renderPolicyActionLabel(
  action: PolicyAction,
  isCompact = true
): React.JSX.Element {
  switch (action) {
    case 'Allow':
      return (
        <Label color="green" isCompact={isCompact} icon={<CheckCircleIcon />}>
          Allow
        </Label>
      );
    case 'BlockNxDomain':
      return (
        <Label color="red" isCompact={isCompact} icon={<BanIcon />}>
          Block (NXDOMAIN)
        </Label>
      );
    case 'Sinkhole':
      return (
        <Label color="orange" isCompact={isCompact} icon={<LockIcon />}>
          Sinkhole Redirect
        </Label>
      );
    default:
      return assertNever(action);
  }
}

export function PolicyRuleDirectoryCard({
  rules,
  selectedRule,
  total,
  page,
  perPage,
  searchInput,
  matchModeFilter,
  actionFilter,
  isLoading,
  isReadOnly,
  onSelectRule,
  onSearchChange,
  onMatchModeFilterChange,
  onActionFilterChange,
  onClearFilters,
  onPageChange,
  onPerPageChange,
  onOpenAddModal
}: PolicyRuleDirectoryCardProps): React.JSX.Element {
  const hasActiveFilters =
    searchInput.trim().length > 0 ||
    matchModeFilter !== 'ALL' ||
    actionFilter !== 'ALL';

  return (
    <Card isFullHeight>
      <CardHeader>
        <Flex
          justifyContent={{ default: 'justifyContentSpaceBetween' }}
          alignItems={{ default: 'alignItemsCenter' }}
          gap={{ default: 'gapSm' }}
        >
          <FlexItem>
            <CardTitle>
              <Flex
                spaceItems={{ default: 'spaceItemsSm' }}
                alignItems={{ default: 'alignItemsCenter' }}
              >
                <FlexItem>Policy Rules</FlexItem>
                <FlexItem>
                  <Badge isRead>{total}</Badge>
                </FlexItem>
              </Flex>
            </CardTitle>
          </FlexItem>
          {!isReadOnly && (
            <FlexItem>
              <Button
                variant="primary"
                size="sm"
                icon={<PlusCircleIcon />}
                onClick={onOpenAddModal}
              >
                Create rule
              </Button>
            </FlexItem>
          )}
        </Flex>
      </CardHeader>

      <Divider />

      <CardBody isFilled>
        <Stack hasGutter>
          <StackItem>
            <SearchInput
              placeholder="Filter rules by domain pattern or comment..."
              value={searchInput}
              onChange={(_event, val) => {
                onSearchChange(val);
                onPageChange(1);
              }}
              onClear={() => {
                onSearchChange('');
                onPageChange(1);
              }}
              aria-label="Search protective DNS policy rules"
            />
          </StackItem>

          <StackItem>
            <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
              <FlexItem flex={{ default: 'flex_1' }} style={{ minWidth: '130px' }}>
                <FormSelect
                  value={matchModeFilter}
                  onChange={(_event, val) => {
                    onMatchModeFilterChange(val as RuleMatchModeFilter);
                  }}
                  aria-label="Filter by match mode"
                >
                  <FormSelectOption value="ALL" label="All match modes" />
                  <FormSelectOption value="Suffix" label="Suffix match" />
                  <FormSelectOption value="Exact" label="Exact match" />
                </FormSelect>
              </FlexItem>

              <FlexItem flex={{ default: 'flex_1' }} style={{ minWidth: '130px' }}>
                <FormSelect
                  value={actionFilter}
                  onChange={(_event, val) => {
                    onActionFilterChange(val as RuleActionFilter);
                  }}
                  aria-label="Filter by enforcement action"
                >
                  <FormSelectOption value="ALL" label="All actions" />
                  <FormSelectOption value="BlockNxDomain" label="Block (NXDOMAIN)" />
                  <FormSelectOption value="Sinkhole" label="Sinkhole redirect" />
                  <FormSelectOption value="Allow" label="Explicit allow" />
                </FormSelect>
              </FlexItem>

              {hasActiveFilters && (
                <FlexItem>
                  <Button variant="link" size="sm" isInline onClick={onClearFilters}>
                    Reset filters
                  </Button>
                </FlexItem>
              )}
            </Flex>
          </StackItem>

          <StackItem>
            {isLoading ? (
              <EmptyState
                variant="sm"
                titleText="Loading policy rules"
                headingLevel="h3"
                icon={Spinner}
              />
            ) : rules.length === 0 ? (
              <EmptyState
                variant="sm"
                titleText={
                  hasActiveFilters ? 'No matching policy rules' : 'No policy rules configured'
                }
                headingLevel="h3"
                icon={hasActiveFilters ? SearchIcon : ShieldAltIcon}
              >
                <EmptyStateBody>
                  {hasActiveFilters
                    ? 'No protective DNS rules matched your current search or filter criteria.'
                    : 'Create your first threat-blocking, sinkhole, or allowlist policy rule.'}
                </EmptyStateBody>
                <EmptyStateFooter>
                  <EmptyStateActions>
                    {hasActiveFilters ? (
                      <Button variant="link" onClick={onClearFilters}>
                        Reset filters
                      </Button>
                    ) : !isReadOnly ? (
                      <Button
                        variant="primary"
                        icon={<PlusCircleIcon />}
                        onClick={onOpenAddModal}
                      >
                        Create rule
                      </Button>
                    ) : null}
                  </EmptyStateActions>
                </EmptyStateFooter>
              </EmptyState>
            ) : (
              <DataList
                aria-label="Protective DNS policy rules directory"
                isCompact
                selectedDataListItemId={selectedRule?.id ?? ''}
                onSelectDataListItem={(_event, id) => {
                  onSelectRule(id);
                }}
              >
                {rules.map((rule) => (
                  <DataListItem
                    key={rule.id}
                    id={rule.id}
                    aria-labelledby={`policy-rule-item-${rule.id}`}
                  >
                    <DataListItemRow>
                      <DataListItemCells
                        dataListCells={[
                          <DataListCell key="primary" isFilled>
                            <Flex
                              direction={{ default: 'column' }}
                              flexWrap={{ default: 'nowrap' }}
                              spaceItems={{ default: 'spaceItemsXs' }}
                            >
                              <FlexItem>
                                <Flex
                                  justifyContent={{
                                    default: 'justifyContentSpaceBetween'
                                  }}
                                  alignItems={{ default: 'alignItemsCenter' }}
                                  gap={{ default: 'gapSm' }}
                                >
                                  <FlexItem>
                                    <span id={`policy-rule-item-${rule.id}`}>
                                      <strong className="pf-v6-u-font-family-monospace">
                                        {rule.pattern}
                                      </strong>
                                    </span>
                                  </FlexItem>
                                  <FlexItem>
                                    {renderPolicyActionLabel(rule.action, true)}
                                  </FlexItem>
                                </Flex>
                              </FlexItem>

                              <FlexItem>
                                <Content component="small">
                                  {rule.comment || 'No operator comment'}
                                </Content>
                              </FlexItem>

                              <FlexItem>
                                <Flex
                                  gap={{ default: 'gapSm' }}
                                  alignItems={{ default: 'alignItemsCenter' }}
                                >
                                  <FlexItem>
                                    <Label
                                      color={
                                        rule.match_mode === 'Suffix' ? 'purple' : 'blue'
                                      }
                                      isCompact
                                      icon={<ShieldAltIcon />}
                                    >
                                      {rule.match_mode} match
                                    </Label>
                                  </FlexItem>
                                </Flex>
                              </FlexItem>
                            </Flex>
                          </DataListCell>
                        ]}
                      />
                    </DataListItemRow>
                  </DataListItem>
                ))}
              </DataList>
            )}
          </StackItem>

          {total > perPage && (
            <StackItem>
              <Divider />
              <Pagination
                itemCount={total}
                perPage={perPage}
                page={page}
                perPageOptions={[...PER_PAGE_OPTIONS]}
                onSetPage={(_event, newPage) => {
                  onPageChange(newPage);
                }}
                onPerPageSelect={(_event, newPerPage) => {
                  onPerPageChange(newPerPage);
                  onPageChange(1);
                }}
                variant="bottom"
                isCompact
                isStatic
                titles={{
                  paginationAriaLabel: 'Protective DNS policy rules pagination'
                }}
              />
            </StackItem>
          )}
        </Stack>
      </CardBody>
    </Card>
  );
}
