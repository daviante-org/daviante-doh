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
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { PER_PAGE_OPTIONS } from '../../../constants';
import { formatEpochSeconds } from '../../../utils';
import type { AuditEventEntry } from '../types/telemetry.types';

export interface AdminAuditTrailCardProps {
  readonly auditEvents: readonly AuditEventEntry[];
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
  readonly onPageChange: (page: number) => void;
  readonly onPerPageChange: (perPage: number) => void;
}

export function AdminAuditTrailCard({
  auditEvents,
  total,
  page,
  perPage,
  onPageChange,
  onPerPageChange
}: AdminAuditTrailCardProps): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Administrative Security Audit Trail ({total})</CardTitle>
      </CardHeader>
      <CardBody>
        <Toolbar id="audit-log-toolbar">
          <ToolbarContent>
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

        {auditEvents.length === 0 ? (
          <EmptyState titleText="No administrative audit events" headingLevel="h4">
            <EmptyStateBody>
              Logins, logouts, and DNS/policy modifications are recorded here.
            </EmptyStateBody>
          </EmptyState>
        ) : (
          <Table aria-label="Administrative security audit log table" variant="compact">
            <Thead>
              <Tr>
                <Th>Time</Th>
                <Th>Actor</Th>
                <Th>Role</Th>
                <Th>Action</Th>
                <Th>Target Resource</Th>
                <Th>Outcome</Th>
              </Tr>
            </Thead>
            <Tbody>
              {auditEvents.map((ev, idx) => (
                <Tr key={`${String(ev.timestamp_epoch)}-${ev.action}-${String(idx)}`}>
                  <Td dataLabel="Time">{formatEpochSeconds(ev.timestamp_epoch)}</Td>
                  <Td dataLabel="Actor">
                    <strong>{ev.actor}</strong>
                  </Td>
                  <Td dataLabel="Role">
                    <Label isCompact color="blue">
                      {ev.role}
                    </Label>
                  </Td>
                  <Td dataLabel="Action">
                    <code>{ev.action}</code>
                  </Td>
                  <Td dataLabel="Target Resource">{ev.target}</Td>
                  <Td dataLabel="Outcome">
                    <Label isCompact color={ev.outcome === 'success' ? 'green' : 'orange'}>
                      {ev.outcome}
                    </Label>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
}
