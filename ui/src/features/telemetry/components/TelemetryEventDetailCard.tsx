import React from 'react';
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Content,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Divider,
  Flex,
  FlexItem,
  Label,
  Stack,
  StackItem
} from '@patternfly/react-core';
import {
  BanIcon,
  CheckCircleIcon,
  LockIcon,
  ShieldAltIcon
} from '@patternfly/react-icons';
import { formatUpdatedEpoch } from '../../../utils';
import type { TelemetryStreamMode } from '../hooks/useTelemetryDashboard';
import type {
  AuditEventEntry,
  DnsActivityEntry,
  TelemetrySummaryResponse
} from '../types/telemetry.types';
import { TelemetryKpiGrid } from './TelemetryKpiGrid';
import { UpstreamHealthCard } from './UpstreamHealthCard';

export interface TelemetryEventDetailCardProps {
  readonly streamMode: TelemetryStreamMode;
  readonly summary: TelemetrySummaryResponse | null;
  readonly selectedActivity: DnsActivityEntry | null;
  readonly selectedAuditEvent: AuditEventEntry | null;
}

export function TelemetryEventDetailCard({
  streamMode,
  summary,
  selectedActivity,
  selectedAuditEvent
}: TelemetryEventDetailCardProps): React.JSX.Element {
  return (
    <Card isFullHeight>
      <CardHeader>
        {streamMode === 'activity' && selectedActivity ? (
          <Flex
            direction={{ default: 'column' }}
            flexWrap={{ default: 'nowrap' }}
            spaceItems={{ default: 'spaceItemsXs' }}
          >
            <FlexItem>
              <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                <FlexItem>
                  <CardTitle className="pf-v6-u-font-family-monospace">
                    {selectedActivity.question_name} IN {selectedActivity.question_type}
                  </CardTitle>
                </FlexItem>
                <FlexItem>
                  <Label color="blue" icon={<ShieldAltIcon />}>
                    {selectedActivity.outcome}
                  </Label>
                </FlexItem>
                <FlexItem>
                  <Label color="green" icon={<CheckCircleIcon />}>
                    {selectedActivity.response_code}
                  </Label>
                </FlexItem>
              </Flex>
            </FlexItem>
            <FlexItem>
              <Content component="p">
                Client IP: <code>{selectedActivity.client_ip}</code> &bull; Latency:{' '}
                <strong>{selectedActivity.latency_ms.toFixed(2)} ms</strong>
              </Content>
            </FlexItem>
            <FlexItem>
              <Content component="small">
                Recorded {formatUpdatedEpoch(selectedActivity.timestamp_epoch)}
              </Content>
            </FlexItem>
          </Flex>
        ) : streamMode === 'audit' && selectedAuditEvent ? (
          <Flex
            direction={{ default: 'column' }}
            flexWrap={{ default: 'nowrap' }}
            spaceItems={{ default: 'spaceItemsXs' }}
          >
            <FlexItem>
              <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                <FlexItem>
                  <CardTitle className="pf-v6-u-font-family-monospace">
                    {selectedAuditEvent.action}
                  </CardTitle>
                </FlexItem>
                <FlexItem>
                  <Label color="blue" icon={<LockIcon />}>
                    {selectedAuditEvent.actor} ({selectedAuditEvent.role})
                  </Label>
                </FlexItem>
                <FlexItem>
                  <Label
                    color={
                      selectedAuditEvent.outcome.toLowerCase() === 'success'
                        ? 'green'
                        : 'orange'
                    }
                    icon={
                      selectedAuditEvent.outcome.toLowerCase() === 'success' ? (
                        <CheckCircleIcon />
                      ) : (
                        <BanIcon />
                      )
                    }
                  >
                    {selectedAuditEvent.outcome}
                  </Label>
                </FlexItem>
              </Flex>
            </FlexItem>
            <FlexItem>
              <Content component="p">
                Target resource: <code>{selectedAuditEvent.target}</code>
              </Content>
            </FlexItem>
            <FlexItem>
              <Content component="small">
                Recorded {formatUpdatedEpoch(selectedAuditEvent.timestamp_epoch)}
              </Content>
            </FlexItem>
          </Flex>
        ) : (
          <CardTitle>Resolver Telemetry &amp; Forensic Inspector</CardTitle>
        )}
      </CardHeader>

      <Divider />

      <CardBody isFilled>
        <Stack hasGutter>
          {/* Section 1: Selected Event Forensic Details */}
          <StackItem>
            <Card isCompact variant="secondary">
              <CardHeader>
                <Flex
                  justifyContent={{ default: 'justifyContentSpaceBetween' }}
                  alignItems={{ default: 'alignItemsCenter' }}
                  gap={{ default: 'gapSm' }}
                >
                  <FlexItem>
                    <strong>
                      {streamMode === 'activity'
                        ? 'Selected DNS Query Forensic Attributes'
                        : 'Selected Admin Security Audit Attributes'}
                    </strong>
                  </FlexItem>
                  <FlexItem>
                    <Badge isRead>
                      {streamMode === 'activity' ? 'DNS Ring Buffer' : 'Audit Trail'}
                    </Badge>
                  </FlexItem>
                </Flex>
              </CardHeader>

              <Divider />

              <CardBody>
                {streamMode === 'activity' && selectedActivity ? (
                  <DescriptionList
                    isCompact
                    columnModifier={{ default: '1Col', md: '3Col' }}
                  >
                    <DescriptionListGroup>
                      <DescriptionListTerm>Question Name (QNAME)</DescriptionListTerm>
                      <DescriptionListDescription>
                        <code>{selectedActivity.question_name}</code>
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Question Type (QTYPE)</DescriptionListTerm>
                      <DescriptionListDescription>
                        <code>{selectedActivity.question_type}</code>
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Client Address</DescriptionListTerm>
                      <DescriptionListDescription>
                        <code>{selectedActivity.client_ip}</code>
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Pipeline Outcome</DescriptionListTerm>
                      <DescriptionListDescription>
                        {selectedActivity.outcome}
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Response Code (RCODE)</DescriptionListTerm>
                      <DescriptionListDescription>
                        {selectedActivity.response_code}
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Resolution Latency</DescriptionListTerm>
                      <DescriptionListDescription>
                        {selectedActivity.latency_ms.toFixed(2)} ms
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                  </DescriptionList>
                ) : streamMode === 'audit' && selectedAuditEvent ? (
                  <DescriptionList
                    isCompact
                    columnModifier={{ default: '1Col', md: '3Col' }}
                  >
                    <DescriptionListGroup>
                      <DescriptionListTerm>Authenticated Principal</DescriptionListTerm>
                      <DescriptionListDescription>
                        <code>{selectedAuditEvent.actor}</code>
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>RBAC Role</DescriptionListTerm>
                      <DescriptionListDescription>
                        {selectedAuditEvent.role}
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Security Action</DescriptionListTerm>
                      <DescriptionListDescription>
                        <code>{selectedAuditEvent.action}</code>
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Target Resource</DescriptionListTerm>
                      <DescriptionListDescription>
                        <code>{selectedAuditEvent.target}</code>
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Outcome</DescriptionListTerm>
                      <DescriptionListDescription>
                        {selectedAuditEvent.outcome}
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Timestamp</DescriptionListTerm>
                      <DescriptionListDescription>
                        {formatUpdatedEpoch(selectedAuditEvent.timestamp_epoch)}
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                  </DescriptionList>
                ) : (
                  <Content component="small">
                    Select an event from the directory on the left to inspect its attributes.
                  </Content>
                )}
              </CardBody>
            </Card>
          </StackItem>

          {/* Section 2: Resolver KPI Counters */}
          {summary !== null && (
            <>
              <StackItem>
                <TelemetryKpiGrid summary={summary} />
              </StackItem>

              <StackItem>
                <UpstreamHealthCard summary={summary} />
              </StackItem>
            </>
          )}
        </Stack>
      </CardBody>
    </Card>
  );
}
