import React from 'react';
import {
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Label,
  Stack,
  StackItem
} from '@patternfly/react-core';
import type { LookupResultSummaryCardProps } from '../types/lookup.types';
import { LookupRecordSectionTable } from './LookupRecordSectionTable';

export function LookupResultSummaryCard({
  result
}: LookupResultSummaryCardProps): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Resolution Summary &amp; Answer Sections</CardTitle>
      </CardHeader>
      <CardBody>
        <Stack hasGutter>
          <StackItem>
            <DescriptionList isHorizontal columnModifier={{ default: '3Col' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Response Code (RCODE)</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label
                    color={
                      result.response_code === 'NoError'
                        ? 'green'
                        : result.response_code === 'NXDomain'
                          ? 'orange'
                          : 'red'
                    }
                  >
                    {result.response_code}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>

              <DescriptionListGroup>
                <DescriptionListTerm>Resolution Source</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label color="blue">{result.resolution_source}</Label>
                </DescriptionListDescription>
              </DescriptionListGroup>

              <DescriptionListGroup>
                <DescriptionListTerm>Round-Trip Latency</DescriptionListTerm>
                <DescriptionListDescription>
                  <strong>{result.latency_ms.toFixed(2)} ms</strong>
                </DescriptionListDescription>
              </DescriptionListGroup>

              <DescriptionListGroup>
                <DescriptionListTerm>Question</DescriptionListTerm>
                <DescriptionListDescription>
                  <code>
                    {result.question_name} IN {result.question_type}
                  </code>
                </DescriptionListDescription>
              </DescriptionListGroup>

              <DescriptionListGroup>
                <DescriptionListTerm>Authenticated Data (AD)</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label isCompact color={result.authenticated_data ? 'green' : 'grey'}>
                    {result.authenticated_data ? 'AD=1 (DNSSEC Verified)' : 'AD=0'}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>

              <DescriptionListGroup>
                <DescriptionListTerm>Checking Disabled (CD)</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label isCompact color={result.checking_disabled ? 'orange' : 'grey'}>
                    {result.checking_disabled ? 'CD=1' : 'CD=0'}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </StackItem>

          <StackItem>
            <LookupRecordSectionTable title="Answer Section" records={result.answers} />
          </StackItem>

          {result.authorities.length > 0 && (
            <StackItem>
              <LookupRecordSectionTable title="Authority Section" records={result.authorities} />
            </StackItem>
          )}

          {result.additionals.length > 0 && (
            <StackItem>
              <LookupRecordSectionTable title="Additional Section" records={result.additionals} />
            </StackItem>
          )}
        </Stack>
      </CardBody>
    </Card>
  );
}
