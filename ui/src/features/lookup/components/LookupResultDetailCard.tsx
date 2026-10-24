import React from 'react';
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  CodeBlock,
  CodeBlockCode,
  Content,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Divider,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
  Label,
  Stack,
  StackItem
} from '@patternfly/react-core';
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  SearchIcon,
  ShieldAltIcon
} from '@patternfly/react-icons';
import type { LookupHistoryEntry } from '../hooks/useDnsLookup';
import type { DnsLookupResponse } from '../types/lookup.types';
import { LookupRecordSectionTable } from './LookupRecordSectionTable';

export interface LookupResultDetailCardProps {
  readonly result: DnsLookupResponse | null;
  readonly selectedEntry: LookupHistoryEntry | null;
}

export function LookupResultDetailCard({
  result,
  selectedEntry
}: LookupResultDetailCardProps): React.JSX.Element {
  if (!result) {
    return (
      <Card isFullHeight>
        <CardBody isFilled>
          <EmptyState
            variant="lg"
            titleText="Execute or select a DNS lookup"
            headingLevel="h2"
            icon={SearchIcon}
          >
            <EmptyStateBody>
              Run a diagnostic query on the left to inspect the resolver pipeline outcome
              (Protective Policy, Local Authoritative Zone, Cache, or Upstream Pool), Answer /
              Authority / Additional sections, and the RFC 8484 JSON payload.
            </EmptyStateBody>
          </EmptyState>
        </CardBody>
      </Card>
    );
  }

  const rcodeColor =
    result.response_code === 'NoError'
      ? 'green'
      : result.response_code === 'NXDomain'
        ? 'orange'
        : 'red';

  return (
    <Card isFullHeight>
      <CardHeader>
        <Flex
          direction={{ default: 'column' }}
          flexWrap={{ default: 'nowrap' }}
          spaceItems={{ default: 'spaceItemsXs' }}
        >
          <FlexItem>
            <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
              <FlexItem>
                <CardTitle className="pf-v6-u-font-family-monospace">
                  {result.question_name} IN {result.question_type}
                </CardTitle>
              </FlexItem>
              <FlexItem>
                <Label
                  color={rcodeColor}
                  icon={
                    result.response_code === 'NoError' ? (
                      <CheckCircleIcon />
                    ) : (
                      <ExclamationTriangleIcon />
                    )
                  }
                >
                  {result.response_code}
                </Label>
              </FlexItem>
              <FlexItem>
                <Label color="blue" icon={<ShieldAltIcon />}>
                  {result.resolution_source}
                </Label>
              </FlexItem>
              <FlexItem>
                <Label color={result.authenticated_data ? 'green' : 'grey'}>
                  {result.authenticated_data ? 'AD=1 (DNSSEC Verified)' : 'AD=0'}
                </Label>
              </FlexItem>
            </Flex>
          </FlexItem>

          <FlexItem>
            <Content component="p">
              Resolved in <strong>{result.latency_ms.toFixed(2)} ms</strong> via{' '}
              <code>{result.resolution_source}</code>
            </Content>
          </FlexItem>

          <FlexItem>
            <Content component="small">
              Executed at {selectedEntry?.executedAt ?? 'now'} &bull; Answers:{' '}
              {String(result.answers.length)} &bull; Authorities:{' '}
              {String(result.authorities.length)} &bull; Additionals:{' '}
              {String(result.additionals.length)}
            </Content>
          </FlexItem>
        </Flex>
      </CardHeader>

      <Divider />

      <CardBody isFilled>
        <Stack hasGutter>
          {/* Section 1: Resolution Summary & DNS Sections */}
          <StackItem>
            <Card isCompact variant="secondary">
              <CardHeader>
                <Flex
                  justifyContent={{ default: 'justifyContentSpaceBetween' }}
                  alignItems={{ default: 'alignItemsCenter' }}
                  gap={{ default: 'gapSm' }}
                >
                  <FlexItem>
                    <strong>Resolution Summary &amp; Answer Sections</strong>
                  </FlexItem>
                  <FlexItem>
                    <Badge isRead={result.answers.length === 0}>
                      {String(result.answers.length)} Answer RR(s)
                    </Badge>
                  </FlexItem>
                </Flex>
              </CardHeader>

              <Divider />

              <CardBody>
                <Stack hasGutter>
                  <StackItem>
                    <DescriptionList
                      isCompact
                      columnModifier={{ default: '1Col', md: '3Col' }}
                    >
                      <DescriptionListGroup>
                        <DescriptionListTerm>Response Code (RCODE)</DescriptionListTerm>
                        <DescriptionListDescription>
                          {result.response_code}
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                      <DescriptionListGroup>
                        <DescriptionListTerm>Resolution Source</DescriptionListTerm>
                        <DescriptionListDescription>
                          {result.resolution_source}
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                      <DescriptionListGroup>
                        <DescriptionListTerm>Round-Trip Latency</DescriptionListTerm>
                        <DescriptionListDescription>
                          {result.latency_ms.toFixed(2)} ms
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                    </DescriptionList>
                  </StackItem>

                  <StackItem>
                    <LookupRecordSectionTable
                      title="Answer Section"
                      records={result.answers}
                    />
                  </StackItem>

                  {result.authorities.length > 0 && (
                    <StackItem>
                      <LookupRecordSectionTable
                        title="Authority Section"
                        records={result.authorities}
                      />
                    </StackItem>
                  )}

                  {result.additionals.length > 0 && (
                    <StackItem>
                      <LookupRecordSectionTable
                        title="Additional Section"
                        records={result.additionals}
                      />
                    </StackItem>
                  )}
                </Stack>
              </CardBody>
            </Card>
          </StackItem>

          {/* Section 2: RFC 8484 Structured Diagnostic JSON Payload */}
          <StackItem>
            <Card isCompact variant="secondary">
              <CardHeader>
                <Flex
                  justifyContent={{ default: 'justifyContentSpaceBetween' }}
                  alignItems={{ default: 'alignItemsCenter' }}
                  gap={{ default: 'gapSm' }}
                >
                  <FlexItem>
                    <strong>RFC 8484 Structured Diagnostic JSON Payload</strong>
                  </FlexItem>
                  <FlexItem>
                    <Badge isRead>application/dns-json</Badge>
                  </FlexItem>
                </Flex>
              </CardHeader>

              <Divider />

              <CardBody>
                <CodeBlock>
                  <CodeBlockCode id="dns-lookup-json-output">
                    {JSON.stringify(result, null, 2)}
                  </CodeBlockCode>
                </CodeBlock>
              </CardBody>
            </Card>
          </StackItem>
        </Stack>
      </CardBody>
    </Card>
  );
}
