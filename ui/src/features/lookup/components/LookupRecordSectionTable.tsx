import React from 'react';
import {
  Content,
  ContentVariants,
  EmptyState,
  EmptyStateBody,
  Label,
  Stack,
  StackItem
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import type { LookupRecordSectionTableProps } from '../types/lookup.types';

export function LookupRecordSectionTable({
  title,
  records
}: LookupRecordSectionTableProps): React.JSX.Element {
  return (
    <Stack hasGutter>
      <StackItem>
        <Content component={ContentVariants.h3}>
          {title} ({records.length})
        </Content>
      </StackItem>
      <StackItem>
        {records.length === 0 ? (
          <EmptyState titleText={`No ${title.toLowerCase()}`} headingLevel="h4">
            <EmptyStateBody>
              The DNS response did not include any records in this section.
            </EmptyStateBody>
          </EmptyState>
        ) : (
          <Table aria-label={title} variant="compact">
            <Thead>
              <Tr>
                <Th>Name</Th>
                <Th>RR Type</Th>
                <Th>TTL (s)</Th>
                <Th>RDATA / Wire Presentation</Th>
              </Tr>
            </Thead>
            <Tbody>
              {records.map((rec, idx) => (
                <Tr key={`${rec.name}-${rec.rr_type}-${String(idx)}`}>
                  <Td dataLabel="Name">
                    <strong>{rec.name}</strong>
                  </Td>
                  <Td dataLabel="RR Type">
                    <Label isCompact color="blue">
                      {rec.rr_type}
                    </Label>
                  </Td>
                  <Td dataLabel="TTL (s)">{rec.ttl}</Td>
                  <Td dataLabel="RDATA">
                    <code>{rec.rdata}</code>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </StackItem>
    </Stack>
  );
}
