import React from 'react';
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
  Label,
  Pagination,
  SearchInput,
  Spinner,
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { PER_PAGE_OPTIONS } from '../../../constants';
import { assertNever } from '../../../utils';
import type { PolicyAction, PolicyRulesTableCardProps } from '../types/policy.types';

function formatActionBadge(action: PolicyAction): {
  label: string;
  color: 'green' | 'red' | 'orange';
} {
  switch (action) {
    case 'Allow':
      return { label: 'Allow (Bypass Block)', color: 'green' };
    case 'BlockNxDomain':
      return { label: 'Block (NXDOMAIN)', color: 'red' };
    case 'Sinkhole':
      return { label: 'Sinkhole (Zero IP)', color: 'orange' };
    default:
      return assertNever(action);
  }
}

export function PolicyRulesTableCard({
  rules,
  total,
  page,
  perPage,
  searchInput,
  isLoading,
  isReadOnly,
  onSearchChange,
  onPageChange,
  onPerPageChange,
  onOpenAddModal,
  onDeleteRule
}: PolicyRulesTableCardProps): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Domain Allowlist &amp; Blocklist Rules ({total})</CardTitle>
      </CardHeader>
      <CardBody>
        <Toolbar id="policy-rules-toolbar">
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                aria-label="Filter policy rules"
                placeholder="Search pattern or comment..."
                value={searchInput}
                onChange={(_event, val) => {
                  onSearchChange(val);
                  onPageChange(1);
                }}
                onClear={() => {
                  onSearchChange('');
                  onPageChange(1);
                }}
              />
            </ToolbarItem>
            {!isReadOnly && (
              <ToolbarItem>
                <Button variant="primary" onClick={onOpenAddModal}>
                  Add Policy Rule
                </Button>
              </ToolbarItem>
            )}
            <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
              <Pagination
                itemCount={total}
                perPage={perPage}
                page={page}
                perPageOptions={[...PER_PAGE_OPTIONS]}
                onSetPage={(_event, nextPage) => { onPageChange(nextPage); }}
                onPerPageSelect={(_event, nextPerPage) => {
                  onPerPageChange(Math.min(nextPerPage, 100));
                  onPageChange(1);
                }}
                isCompact
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>

        {isLoading ? (
          <EmptyState titleText="Loading policy rules" headingLevel="h3" icon={Spinner}>
            <EmptyStateBody>Retrieving protective DNS rules...</EmptyStateBody>
          </EmptyState>
        ) : rules.length === 0 ? (
          <EmptyState titleText="No policy rules configured" headingLevel="h3">
            <EmptyStateBody>
              Add an Exact or Suffix domain rule to block malicious domains or allowlist trusted
              subdomains.
            </EmptyStateBody>
          </EmptyState>
        ) : (
          <Table aria-label="Protective DNS policy rules table" variant="compact">
            <Thead>
              <Tr>
                <Th>Domain Pattern</Th>
                <Th>Match Mode</Th>
                <Th>Enforcement Action</Th>
                <Th>Comment</Th>
                <Th>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {rules.map((rule) => {
                const badge = formatActionBadge(rule.action);
                return (
                  <Tr key={rule.id}>
                    <Td dataLabel="Domain Pattern">
                      <strong>{rule.pattern}</strong>
                    </Td>
                    <Td dataLabel="Match Mode">
                      <Label isCompact color={rule.match_mode === 'Suffix' ? 'purple' : 'blue'}>
                        {rule.match_mode === 'Suffix'
                          ? 'Suffix (*.domain)'
                          : 'Exact Match'}
                      </Label>
                    </Td>
                    <Td dataLabel="Enforcement Action">
                      <Label isCompact color={badge.color}>
                        {badge.label}
                      </Label>
                    </Td>
                    <Td dataLabel="Comment">{rule.comment || '—'}</Td>
                    <Td dataLabel="Actions">
                      {!isReadOnly ? (
                        <Flex gap={{ default: 'gapSm' }}>
                          <FlexItem>
                            <Button
                              variant="danger"
                              size="sm"
                              onClick={() => {
                                void onDeleteRule(rule.id);
                              }}
                            >
                              Delete
                            </Button>
                          </FlexItem>
                        </Flex>
                      ) : (
                        <span>Read-only</span>
                      )}
                    </Td>
                  </Tr>
                );
              })}
            </Tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
}
