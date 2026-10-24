import React from 'react';
import {
  Alert,
  Button,
  Content,
  Flex,
  FlexItem,
  Grid,
  GridItem,
  PageSection,
  Stack,
  StackItem,
  Switch,
  Title
} from '@patternfly/react-core';
import { SyncAltIcon } from '@patternfly/react-icons';
import { useTelemetryDashboard } from '../hooks/useTelemetryDashboard';
import { TelemetryEventDetailCard } from './TelemetryEventDetailCard';
import { TelemetryEventDirectoryCard } from './TelemetryEventDirectoryCard';

export function TelemetryDashboardFeature(): React.JSX.Element {
  const {
    streamMode,
    summary,
    activity,
    selectedActivity,
    selectedActivityIdx,
    activityTotal,
    activityPage,
    activityPerPage,
    activitySearch,
    filteredAuditEvents,
    selectedAuditEvent,
    selectedAuditIdx,
    auditTotal,
    auditPage,
    auditPerPage,
    auditSearch,
    isLoading,
    pageError,
    autoRefresh,
    setStreamMode,
    setSelectedActivityIdx,
    setSelectedAuditIdx,
    setActivityPage,
    setActivityPerPage,
    setActivitySearch,
    setAuditPage,
    setAuditPerPage,
    setAuditSearch,
    setAutoRefresh,
    loadTelemetry
  } = useTelemetryDashboard();

  return (
    <>
      <PageSection>
        <Stack hasGutter>
          <StackItem>
            <Flex
              justifyContent={{ default: 'justifyContentSpaceBetween' }}
              alignItems={{ default: 'alignItemsFlexStart' }}
              gap={{ default: 'gapMd' }}
            >
              <FlexItem>
                <Title headingLevel="h1" size="2xl">
                  Real-Time Telemetry &amp; Audit Log
                </Title>
                <Content component="p">
                  Inspect DoH query throughput, cache efficiency, upstream pool health, recent
                  DNS queries, and administrative security events.
                </Content>
              </FlexItem>
              <FlexItem>
                <Flex gap={{ default: 'gapMd' }} alignItems={{ default: 'alignItemsCenter' }}>
                  <FlexItem>
                    <Switch
                      id="telemetry-auto-refresh"
                      label="Auto-refresh (5s)"
                      isChecked={autoRefresh}
                      onChange={(_e, checked) => {
                        setAutoRefresh(checked);
                      }}
                    />
                  </FlexItem>
                  <FlexItem>
                    <Button
                      variant="secondary"
                      icon={<SyncAltIcon />}
                      isLoading={isLoading}
                      onClick={() => {
                        void loadTelemetry();
                      }}
                    >
                      Refresh
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
        </Stack>
      </PageSection>

      <PageSection isFilled>
        <Grid hasGutter>
          <GridItem span={12} lg={4}>
            <TelemetryEventDirectoryCard
              streamMode={streamMode}
              activity={activity}
              selectedActivityIdx={selectedActivityIdx}
              activityTotal={activityTotal}
              activityPage={activityPage}
              activityPerPage={activityPerPage}
              activitySearch={activitySearch}
              auditEvents={filteredAuditEvents}
              selectedAuditIdx={selectedAuditIdx}
              auditTotal={auditTotal}
              auditPage={auditPage}
              auditPerPage={auditPerPage}
              auditSearch={auditSearch}
              onChangeStreamMode={setStreamMode}
              onSelectActivityIdx={setSelectedActivityIdx}
              onSelectAuditIdx={setSelectedAuditIdx}
              onActivitySearchChange={setActivitySearch}
              onAuditSearchChange={setAuditSearch}
              onActivityPageChange={setActivityPage}
              onActivityPerPageChange={setActivityPerPage}
              onAuditPageChange={setAuditPage}
              onAuditPerPageChange={setAuditPerPage}
            />
          </GridItem>

          <GridItem span={12} lg={8}>
            <TelemetryEventDetailCard
              streamMode={streamMode}
              summary={summary}
              selectedActivity={selectedActivity}
              selectedAuditEvent={selectedAuditEvent}
            />
          </GridItem>
        </Grid>
      </PageSection>
    </>
  );
}
