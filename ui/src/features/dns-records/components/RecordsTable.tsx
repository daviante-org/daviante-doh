import React from 'react';
import {
  Button,
  Checkbox,
  ClipboardCopy,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  Flex,
  FlexItem,
  Label,
  Spinner,
  Switch
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { formatHumanTtl } from '../../../utils';
import type { DnsZoneView, LocalDnsRecordView } from '../types/dnsRecords.types';
import {
  formatOwnerParts,
  formatRecordValueSummary,
  getRecordTypeColor
} from '../utils/recordFormatters';
import { RecordExpandedDetails } from './RecordExpandedDetails';

export interface RecordsTableProps {
  readonly isLoading: boolean;
  readonly visibleRecords: readonly LocalDnsRecordView[];
  readonly activeZone: DnsZoneView | null;
  readonly isReadOnly: boolean;
  readonly expandedRecordIds: ReadonlySet<string>;
  readonly selectedRecordIds: ReadonlySet<string>;
  readonly onToggleExpand: (id: string) => void;
  readonly onToggleSelect: (id: string, checked: boolean) => void;
  readonly onToggleSelectAllPage: (checked: boolean) => void;
  readonly onQuickToggleEnabled: (item: LocalDnsRecordView) => Promise<void>;
  readonly onOpenCreateRecord: () => void;
  readonly onOpenEditRecord: (item: LocalDnsRecordView) => void;
  readonly onOpenCloneRecord: (item: LocalDnsRecordView) => void;
  readonly onOpenDeleteRecord: (item: LocalDnsRecordView) => void;
}

export function RecordsTable({
  isLoading,
  visibleRecords,
  activeZone,
  isReadOnly,
  expandedRecordIds,
  selectedRecordIds,
  onToggleExpand,
  onToggleSelect,
  onToggleSelectAllPage,
  onQuickToggleEnabled,
  onOpenCreateRecord,
  onOpenEditRecord,
  onOpenCloneRecord,
  onOpenDeleteRecord
}: RecordsTableProps): React.JSX.Element {
  if (isLoading) {
    return (
      <EmptyState titleText="Loading local DNS records" headingLevel="h3" icon={Spinner}>
        <EmptyStateBody>Fetching zone records from the DoH server...</EmptyStateBody>
      </EmptyState>
    );
  }

  if (visibleRecords.length === 0) {
    return (
      <EmptyState titleText="No matching local DNS records found" headingLevel="h3">
        <EmptyStateBody>
          {activeZone
            ? `No records in zone '${activeZone.name}' match your current filters. Click "Add Record" to create an authoritative or split-horizon entry.`
            : 'No records match your search or category filter.'}
        </EmptyStateBody>
        {!isReadOnly && (
          <EmptyStateFooter>
            <EmptyStateActions>
              <Button variant="primary" onClick={onOpenCreateRecord}>
                Add Record
              </Button>
            </EmptyStateActions>
          </EmptyStateFooter>
        )}
      </EmptyState>
    );
  }

  return (
    <Table aria-label="Local DNS records table" variant="compact">
      <Thead>
        <Tr>
          <Th screenReaderText="Expand record details" />
          {!isReadOnly && (
            <Th screenReaderText="Select all records on page">
              <Checkbox
                id="select-all-records-checkbox"
                aria-label="Select all records on page"
                isChecked={
                  visibleRecords.length > 0 && selectedRecordIds.size === visibleRecords.length
                }
                onChange={(_e, checked) => { onToggleSelectAllPage(checked); }}
              />
            </Th>
          )}
          <Th width={25}>Owner / Domain</Th>
          <Th width={10}>Type</Th>
          <Th width={30}>Value / Target (RDATA)</Th>
          <Th width={10}>TTL</Th>
          <Th width={10}>Status</Th>
          <Th width={15}>Actions</Th>
        </Tr>
      </Thead>
      {visibleRecords.map((item, rowIndex) => {
        const isExpanded = expandedRecordIds.has(item.id);
        const ownerParts = formatOwnerParts(item.domain, item.zone_name ?? activeZone?.name);
        const valueSummary = formatRecordValueSummary(item.record);

        return (
          <Tbody key={item.id} isExpanded={isExpanded}>
            <Tr>
              <Td
                expand={{
                  rowIndex,
                  isExpanded,
                  onToggle: () => { onToggleExpand(item.id); },
                  expandId: `expand-record-${item.id}`
                }}
              />
              {!isReadOnly && (
                <Td
                  select={{
                    rowIndex,
                    onSelect: (_e, isSelecting) => { onToggleSelect(item.id, isSelecting); },
                    isSelected: selectedRecordIds.has(item.id)
                  }}
                />
              )}
              <Td dataLabel="Owner / Domain">
                <div>
                  <strong>{ownerParts.primaryLabel}</strong>
                  {ownerParts.zoneSuffix && <small>{ownerParts.zoneSuffix}</small>}
                </div>
                {item.zone_name && !activeZone && (
                  <div>
                    <Label isCompact color="teal">
                      Zone: {item.zone_name}
                    </Label>
                  </div>
                )}
                {item.comment && (
                  <div>
                    <small>{item.comment}</small>
                  </div>
                )}
              </Td>
              <Td dataLabel="Type">
                <Label isCompact color={getRecordTypeColor(item.record.type)}>
                  {item.record.type}
                </Label>
              </Td>
              <Td dataLabel="Value / Target">
                <Flex alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapXs' }}>
                  <FlexItem>
                    <ClipboardCopy
                      isReadOnly
                      variant="inline-compact"
                      hoverTip="Copy RDATA value"
                      clickTip="Copied"
                    >
                      {valueSummary.primary}
                    </ClipboardCopy>
                  </FlexItem>
                  {valueSummary.badge && (
                    <FlexItem>
                      <Label isCompact color="grey">
                        {valueSummary.badge}
                      </Label>
                    </FlexItem>
                  )}
                </Flex>
              </Td>
              <Td dataLabel="TTL">
                <Label isCompact>{formatHumanTtl(item.ttl)}</Label>
              </Td>
              <Td dataLabel="Status">
                {!isReadOnly ? (
                  <Switch
                    id={`toggle-enabled-${item.id}`}
                    aria-label={`Enable or disable ${item.domain}`}
                    isChecked={item.enabled}
                    onChange={() => void onQuickToggleEnabled(item)}
                  />
                ) : (
                  <Label isCompact color={item.enabled ? 'green' : 'grey'}>
                    {item.enabled ? 'Active' : 'Disabled'}
                  </Label>
                )}
              </Td>
              <Td dataLabel="Actions">
                {!isReadOnly ? (
                  <Flex gap={{ default: 'gapXs' }}>
                    <FlexItem>
                      <Button variant="secondary" size="sm" onClick={() => { onOpenEditRecord(item); }}>
                        Edit
                      </Button>
                    </FlexItem>
                    <FlexItem>
                      <Button
                        variant="tertiary"
                        size="sm"
                        onClick={() => { onOpenCloneRecord(item); }}
                        aria-label={`Clone ${item.domain}`}
                      >
                        Clone
                      </Button>
                    </FlexItem>
                    <FlexItem>
                      <Button variant="danger" size="sm" onClick={() => { onOpenDeleteRecord(item); }}>
                        Delete
                      </Button>
                    </FlexItem>
                  </Flex>
                ) : (
                  <span>Read-only</span>
                )}
              </Td>
            </Tr>
            {isExpanded && (
              <Tr isExpanded={isExpanded}>
                <Td colSpan={isReadOnly ? 7 : 8}>
                  <RecordExpandedDetails item={item} />
                </Td>
              </Tr>
            )}
          </Tbody>
        );
      })}
    </Table>
  );
}
