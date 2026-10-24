import React from 'react';
import {
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
  EmptyStateBody,
  Flex,
  FlexItem,
  Label,
  Pagination,
  SearchInput,
  Stack,
  StackItem,
  ToggleGroup,
  ToggleGroupItem
} from '@patternfly/react-core';
import {
  BanIcon,
  CheckCircleIcon,
  LockIcon,
  ShieldAltIcon,
  TachometerAltIcon
} from '@patternfly/react-icons';
import { PER_PAGE_OPTIONS } from '../../../constants';
import { formatUpdatedEpoch } from '../../../utils';
import type { TelemetryStreamMode } from '../hooks/useTelemetryDashboard';
import type { AuditEventEntry, DnsActivityEntry } from '../types/telemetry.types';

export interface TelemetryEventDirectoryCardProps {
  readonly streamMode: TelemetryStreamMode;
  readonly activity: readonly DnsActivityEntry[];
  readonly selectedActivityIdx: number;
  readonly activityTotal: number;
  readonly activityPage: number;
  readonly activityPerPage: number;
  readonly activitySearch: string;
  readonly auditEvents: readonly AuditEventEntry[];
  readonly selectedAuditIdx: number;
  readonly auditTotal: number;
  readonly auditPage: number;
  readonly auditPerPage: number;
  readonly auditSearch: string;
  readonly onChangeStreamMode: (mode: TelemetryStreamMode) => void;
  readonly onSelectActivityIdx: (idx: number) => void;
  readonly onSelectAuditIdx: (idx: number) => void;
  readonly onActivitySearchChange: (val: string) => void;
  readonly onAuditSearchChange: (val: string) => void;
  readonly onActivityPageChange: (page: number) => void;
  readonly onActivityPerPageChange: (perPage: number) => void;
  readonly onAuditPageChange: (page: number) => void;
  readonly onAuditPerPageChange: (perPage: number) => void;
}

export function TelemetryEventDirectoryCard({
  streamMode,
  activity,
  selectedActivityIdx,
  activityTotal,
  activityPage,
  activityPerPage,
  activitySearch,
  auditEvents,
  selectedAuditIdx,
  auditTotal,
  auditPage,
  auditPerPage,
  auditSearch,
  onChangeStreamMode,
  onSelectActivityIdx,
  onSelectAuditIdx,
  onActivitySearchChange,
  onAuditSearchChange,
  onActivityPageChange,
  onActivityPerPageChange,
  onAuditPageChange,
  onAuditPerPageChange
}: TelemetryEventDirectoryCardProps): React.JSX.Element {
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
              <ToggleGroup
                isCompact
                aria-label="Switch between DNS activity stream and admin audit log"
              >
                <ToggleGroupItem
                  text={`DNS Queries (${String(activityTotal)})`}
                  buttonId="telemetry-mode-activity"
                  isSelected={streamMode === 'activity'}
                  onChange={() => {
                    onChangeStreamMode('activity');
                  }}
                />
                <ToggleGroupItem
                  text={`Admin Audit (${String(auditTotal)})`}
                  buttonId="telemetry-mode-audit"
                  isSelected={streamMode === 'audit'}
                  onChange={() => {
                    onChangeStreamMode('audit');
                  }}
                />
              </ToggleGroup>
            </CardTitle>
          </FlexItem>
        </Flex>
      </CardHeader>

      <Divider />

      <CardBody isFilled>
        {streamMode === 'activity' ? (
          <Stack hasGutter>
            <StackItem>
              <SearchInput
                placeholder="Filter queries by domain, client IP, or outcome..."
                value={activitySearch}
                onChange={(_event, val) => {
                  onActivitySearchChange(val);
                  onActivityPageChange(1);
                }}
                onClear={() => {
                  onActivitySearchChange('');
                  onActivityPageChange(1);
                }}
                aria-label="Search recent DNS queries"
              />
            </StackItem>

            <StackItem>
              {activity.length === 0 ? (
                <EmptyState
                  variant="sm"
                  titleText="No recent DNS query events"
                  headingLevel="h3"
                  icon={TachometerAltIcon}
                >
                  <EmptyStateBody>
                    No DNS query activity matched your current filter in the telemetry ring
                    buffer.
                  </EmptyStateBody>
                </EmptyState>
              ) : (
                <DataList
                  aria-label="Recent DNS queries directory"
                  isCompact
                  selectedDataListItemId={String(selectedActivityIdx)}
                  onSelectDataListItem={(_event, id) => {
                    const parsed = Number(id);
                    if (!Number.isNaN(parsed)) {
                      onSelectActivityIdx(parsed);
                    }
                  }}
                >
                  {activity.map((item, idx) => {
                    const isBlocked =
                      item.outcome.toLowerCase().includes('block') ||
                      item.outcome.toLowerCase().includes('sinkhole');

                    return (
                      <DataListItem
                        key={`${String(item.timestamp_epoch)}-${item.question_name}-${String(idx)}`}
                        id={String(idx)}
                        aria-labelledby={`activity-item-${String(idx)}`}
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
                                        <span id={`activity-item-${String(idx)}`}>
                                          <strong className="pf-v6-u-font-family-monospace">
                                            {item.question_name}
                                          </strong>
                                        </span>
                                      </FlexItem>
                                      <FlexItem>
                                        <Label
                                          color={isBlocked ? 'orange' : 'green'}
                                          isCompact
                                          icon={isBlocked ? <BanIcon /> : <CheckCircleIcon />}
                                        >
                                          {item.response_code}
                                        </Label>
                                      </FlexItem>
                                    </Flex>
                                  </FlexItem>

                                  <FlexItem>
                                    <Content component="small">
                                      Client: <code>{item.client_ip}</code> &bull;{' '}
                                      {item.latency_ms.toFixed(2)} ms &bull;{' '}
                                      {formatUpdatedEpoch(item.timestamp_epoch)}
                                    </Content>
                                  </FlexItem>

                                  <FlexItem>
                                    <Flex
                                      gap={{ default: 'gapSm' }}
                                      alignItems={{ default: 'alignItemsCenter' }}
                                    >
                                      <FlexItem>
                                        <Label
                                          color="blue"
                                          isCompact
                                          icon={<ShieldAltIcon />}
                                        >
                                          {item.question_type}
                                        </Label>
                                      </FlexItem>
                                      <FlexItem>
                                        <Label color="purple" isCompact variant="outline">
                                          {item.outcome}
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
                    );
                  })}
                </DataList>
              )}
            </StackItem>

            {activityTotal > activityPerPage && (
              <StackItem>
                <Divider />
                <Pagination
                  itemCount={activityTotal}
                  perPage={activityPerPage}
                  page={activityPage}
                  perPageOptions={[...PER_PAGE_OPTIONS]}
                  onSetPage={(_event, newPage) => {
                    onActivityPageChange(newPage);
                  }}
                  onPerPageSelect={(_event, newPerPage) => {
                    onActivityPerPageChange(newPerPage);
                    onActivityPageChange(1);
                  }}
                  variant="bottom"
                  isCompact
                  isStatic
                  titles={{
                    paginationAriaLabel: 'Recent DNS activity pagination'
                  }}
                />
              </StackItem>
            )}
          </Stack>
        ) : (
          <Stack hasGutter>
            <StackItem>
              <SearchInput
                placeholder="Filter audit events by actor, action, or target..."
                value={auditSearch}
                onChange={(_event, val) => {
                  onAuditSearchChange(val);
                }}
                onClear={() => {
                  onAuditSearchChange('');
                }}
                aria-label="Search admin security audit events"
              />
            </StackItem>

            <StackItem>
              {auditEvents.length === 0 ? (
                <EmptyState
                  variant="sm"
                  titleText="No admin audit events"
                  headingLevel="h3"
                  icon={LockIcon}
                >
                  <EmptyStateBody>
                    No administrative security events matched your current filter.
                  </EmptyStateBody>
                </EmptyState>
              ) : (
                <DataList
                  aria-label="Admin security audit directory"
                  isCompact
                  selectedDataListItemId={String(selectedAuditIdx)}
                  onSelectDataListItem={(_event, id) => {
                    const parsed = Number(id);
                    if (!Number.isNaN(parsed)) {
                      onSelectAuditIdx(parsed);
                    }
                  }}
                >
                  {auditEvents.map((evt, idx) => (
                    <DataListItem
                      key={`${String(evt.timestamp_epoch)}-${evt.action}-${String(idx)}`}
                      id={String(idx)}
                      aria-labelledby={`audit-item-${String(idx)}`}
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
                                      <span id={`audit-item-${String(idx)}`}>
                                        <strong className="pf-v6-u-font-family-monospace">
                                          {evt.action}
                                        </strong>
                                      </span>
                                    </FlexItem>
                                    <FlexItem>
                                      <Label
                                        color={
                                          evt.outcome.toLowerCase() === 'success'
                                            ? 'green'
                                            : 'orange'
                                        }
                                        isCompact
                                        icon={<CheckCircleIcon />}
                                      >
                                        {evt.outcome}
                                      </Label>
                                    </FlexItem>
                                  </Flex>
                                </FlexItem>

                                <FlexItem>
                                  <Content component="small">
                                    Target: <code>{evt.target}</code> &bull;{' '}
                                    {formatUpdatedEpoch(evt.timestamp_epoch)}
                                  </Content>
                                </FlexItem>

                                <FlexItem>
                                  <Flex
                                    gap={{ default: 'gapSm' }}
                                    alignItems={{ default: 'alignItemsCenter' }}
                                  >
                                    <FlexItem>
                                      <Label color="blue" isCompact icon={<LockIcon />}>
                                        {evt.actor} ({evt.role})
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

            {auditTotal > auditPerPage && (
              <StackItem>
                <Divider />
                <Pagination
                  itemCount={auditTotal}
                  perPage={auditPerPage}
                  page={auditPage}
                  perPageOptions={[...PER_PAGE_OPTIONS]}
                  onSetPage={(_event, newPage) => {
                    onAuditPageChange(newPage);
                  }}
                  onPerPageSelect={(_event, newPerPage) => {
                    onAuditPerPageChange(newPerPage);
                    onAuditPageChange(1);
                  }}
                  variant="bottom"
                  isCompact
                  isStatic
                  titles={{
                    paginationAriaLabel: 'Admin security audit pagination'
                  }}
                />
              </StackItem>
            )}
          </Stack>
        )}
      </CardBody>
    </Card>
  );
}
