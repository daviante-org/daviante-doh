import React from 'react';
import { Card, CardBody, CardHeader, CardTitle, Label } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import type { TelemetrySummaryResponse } from '../types/telemetry.types';

export interface UpstreamHealthCardProps {
  readonly summary: TelemetrySummaryResponse;
}

export function UpstreamHealthCard({ summary }: UpstreamHealthCardProps): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Upstream Resolver Pool Health</CardTitle>
      </CardHeader>
      <CardBody>
        <Table aria-label="Upstream resolvers health table" variant="compact">
          <Thead>
            <Tr>
              <Th>Upstream Resolver Socket</Th>
              <Th>Health Probe Status</Th>
              <Th>Total Upstream Forwards</Th>
              <Th>Upstream Failures</Th>
            </Tr>
          </Thead>
          <Tbody>
            {summary.upstreams.map((up) => (
              <Tr key={up.address}>
                <Td dataLabel="Upstream Resolver Socket">
                  <code>{up.address}</code>
                </Td>
                <Td dataLabel="Health Probe Status">
                  <Label isCompact color={up.healthy ? 'green' : 'red'}>
                    {up.healthy ? 'Healthy' : 'Unreachable / Degraded'}
                  </Label>
                </Td>
                <Td dataLabel="Total Upstream Forwards">
                  {summary.upstream_Forwards.toLocaleString()}
                </Td>
                <Td dataLabel="Upstream Failures">{summary.upstream_failures.toLocaleString()}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardBody>
    </Card>
  );
}
