import React from 'react';
import {
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  EmptyState,
  EmptyStateBody,
  Label,
  Pagination,
  SearchInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { PER_PAGE_OPTIONS } from '../../../constants';
import { formatEpochSeconds } from '../../../utils';
import type { DnsActivityEntry } from '../types/telemetry.types';

export interface RecentDnsActivityCardProps {
  readonly activity: readonly DnsActivityEntry[];
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
  readonly search: string;
  readonly onSearchChange: (val: string) => void;
  readonly onPageChange: (page: number) => void;
  readonly onPerPageChange: (perPage: number) => void;
}

export function RecentDnsActivityCard({
  activity,
  total,
  page,
  perPage,
  search,
  onSearchChange,
  onPageChange,
  onPerPageChange
}: RecentDnsActivityCardProps): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent DNS Query Activity ({total})</CardTitle>
      </CardHeader>
      <CardBody>
        <Toolbar id="activity-log-toolbar">
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                aria-label="Filter recent DNS queries"
                placeholder="Filter by domain, outcome, or client IP..."
                value={search}
                onChange={(_e, val) => {
                  onSearchChange(val);
                  onPageChange(1);
                }}
                onClear={() => {
                  onSearchChange('');
                  onPageChange(1);
                }}
              />
            </ToolbarItem>
            <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
              <Pagination
                itemCount={total}
                perPage={perPage}
                page={page}
                perPageOptions={[...PER_PAGE_OPTIONS]}
                onSetPage={(_e, nextPage) => { onPageChange(nextPage); }}
                onPerPageSelect={(_e, nextPerPage) => {
                  onPerPageChange(Math.min(nextPerPage, 100));
                  onPageChange(1);
                }}
                isCompact
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>

        {activity.length === 0 ? (
          <EmptyState titleText="No DNS query activity recorded yet" headingLevel="h4">
            <EmptyStateBody>
              Execute a lookup in the Live DNS Lookup Tester or send a DoH query to{' '}
              <code>/dns-query</code>.
            </EmptyStateBody>
          </EmptyState>
        ) : (
          <Table aria-label="Recent DNS queries table" variant="compact">
            <Thead>
              <Tr>
                <Th>Time</Th>
                <Th>Client IP</Th>
                <Th>Question</Th>
                <Th>RR Type</Th>
                <Th>Resolution Outcome</Th>
                <Th>RCODE</Th>
                <Th>Latency</Th>
              </Tr>
            </Thead>
            <Tbody>
              {activity.map((item, idx) => (
                <Tr key={`${String(item.timestamp_epoch)}-${item.question_name}-${String(idx)}`}>
                  <Td dataLabel="Time">{formatEpochSeconds(item.timestamp_epoch)}</Td>
                  <Td dataLabel="Client IP">
                    <code>{item.client_ip}</code>
                  </Td>
                  <Td dataLabel="Question">
                    <strong>{item.question_name}</strong>
                  </Td>
                  <Td dataLabel="RR Type">
                    <Label isCompact color="blue">
                      {item.question_type}
                    </Label>
                  </Td>
                  <Td dataLabel="Resolution Outcome">
                    <Label isCompact>{item.outcome}</Label>
                  </Td>
                  <Td dataLabel="RCODE">{item.response_code}</Td>
                  <Td dataLabel="Latency">{item.latency_ms.toFixed(2)} ms</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
}
