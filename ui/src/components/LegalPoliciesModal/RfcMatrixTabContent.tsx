import React from 'react';
import { Label } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { RFC_STANDARDS_MATRIX } from '../../constants';

export function RfcMatrixTabContent(): React.JSX.Element {
  return (
    <div className="pf-v6-u-pt-md">
      <Table aria-label="RFC and Security Compliance Matrix" variant="compact">
        <Thead>
          <Tr>
            <Th width={20}>Standard / RFC</Th>
            <Th width={30}>Specification Title</Th>
            <Th width={35}>Control-Plane & Engine Scope</Th>
            <Th width={15}>Status</Th>
          </Tr>
        </Thead>
        <Tbody>
          {RFC_STANDARDS_MATRIX.map((row) => (
            <Tr key={row.rfc}>
              <Td dataLabel="Standard / RFC">
                <strong>{row.rfc}</strong>
              </Td>
              <Td dataLabel="Specification Title">{row.title}</Td>
              <Td dataLabel="Scope">{row.scope}</Td>
              <Td dataLabel="Status">
                <Label isCompact color={row.status === 'Enforced' ? 'green' : 'blue'}>
                  {row.status}
                </Label>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </div>
  );
}
