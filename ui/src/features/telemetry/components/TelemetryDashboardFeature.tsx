import React from 'react';
import {
  Alert,
  Button,
  Content,
  ContentVariants,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
  PageSection,
  Spinner,
  Stack,
  StackItem,
  Switch
} from '@patternfly/react-core';
import { useTelemetryDashboard } from '../hooks/useTelemetryDashboard';
import { AdminAuditTrailCard } from './AdminAuditTrailCard';
import { RecentDnsActivityCard } from './RecentDnsActivityCard';
import { TelemetryKpiGrid } from './TelemetryKpiGrid';
import { UpstreamHealthCard } from './UpstreamHealthCard';

export function TelemetryDashboardFeature(): React.JSX.Element {
  const {
    summary,
    activity,
    activityTotal,
    activityPage,
    activityPerPage,
    activitySearch,
    auditEvents,
    auditTotal,
    auditPage,
    auditPerPage,
    isLoading,
    pageError,
    autoRefresh,
    setActivityPage,
    setActivityPerPage,
    setActivitySearch,
    setAuditPage,
    setAuditPerPage,
    setAutoRefresh,
    loadTelemetry
  } = useTelemetryDashboard();

  return (
    <PageSection isFilled>
      <Stack hasGutter>
        <StackItem>
          <Flex
            justifyContent={{ default: 'justifyContentSpaceBetween' }}
            alignItems={{ default: 'alignItemsCenter' }}
            gap={{ default: 'gapSm' }}
          >
            <FlexItem>
              <Content component={ContentVariants.h1}>
                Real-Time Telemetry &amp; Audit Log
              </Content>
              <Content component={ContentVariants.p}>
                Inspect DoH query throughput, cache efficiency, upstream pool health, recent DNS
                queries, and administrative security events.
              </Content>
            </FlexItem>
            <FlexItem>
              <Flex gap={{ default: 'gapMd' }} alignItems={{ default: 'alignItemsCenter' }}>
                <FlexItem>
                  <Switch
                    id="telemetry-auto-refresh"
                    label="Auto-refresh (5s)"
                    isChecked={autoRefresh}
                    onChange={(_e, checked) => { setAutoRefresh(checked); }}
                  />
                </FlexItem>
                <FlexItem>
                  <Button variant="secondary" onClick={() => void loadTelemetry()}>
                    Refresh Now
                  </Button>
                </FlexItem>
              </Flex>
            </FlexItem>
          </Flex>
        </StackItem>

        {pageError !== null && (
          <StackItem>
            <Alert variant="danger" isInline title={pageError} />
          </StackItem>
        )}

        {isLoading || summary === null ? (
          <StackItem>
            <EmptyState titleText="Loading telemetry metrics" headingLevel="h3" icon={Spinner}>
              <EmptyStateBody>Fetching real-time counters and activity ring-buffer...</EmptyStateBody>
            </EmptyState>
          </StackItem>
        ) : (
          <>
            <StackItem>
              <TelemetryKpiGrid summary={summary} />
            </StackItem>
            <StackItem>
              <UpstreamHealthCard summary={summary} />
            </StackItem>
            <StackItem>
              <RecentDnsActivityCard
                activity={activity}
                total={activityTotal}
                page={activityPage}
                perPage={activityPerPage}
                search={activitySearch}
                onSearchChange={setActivitySearch}
                onPageChange={setActivityPage}
                onPerPageChange={setActivityPerPage}
              />
            </StackItem>
            <StackItem>
              <AdminAuditTrailCard
                auditEvents={auditEvents}
                total={auditTotal}
                page={auditPage}
                perPage={auditPerPage}
                onPageChange={setAuditPage}
                onPerPageChange={setAuditPerPage}
              />
            </StackItem>
          </>
        )}
      </Stack>
    </PageSection>
  );
}
