import React from 'react';
import {
  Alert,
  Content,
  Grid,
  GridItem,
  PageSection,
  Stack,
  StackItem,
  Title
} from '@patternfly/react-core';
import { useDnsLookup } from '../hooks/useDnsLookup';
import { LookupQueryDirectoryCard } from './LookupQueryDirectoryCard';
import { LookupResultDetailCard } from './LookupResultDetailCard';

export function DnsLookupTesterFeature(): React.JSX.Element {
  const {
    form,
    result,
    selectedEntry,
    history,
    setSelectedHistoryId,
    lookupError,
    isRunning,
    onSubmit
  } = useDnsLookup();

  return (
    <>
      <PageSection>
        <Stack hasGutter>
          <StackItem>
            <Title headingLevel="h1" size="2xl">
              Live DNS Lookup &amp; Policy Tester
            </Title>
            <Content component="p">
              Test domain resolution directly against the DoH server pipeline (Protective DNS
              Policy → Local Overrides / CNAME Chain → Upstream Pool + DNS Rebinding Guard).
            </Content>
          </StackItem>

          {lookupError !== null && (
            <StackItem>
              <Alert variant="danger" isInline title={lookupError} />
            </StackItem>
          )}
        </Stack>
      </PageSection>

      <PageSection isFilled>
        <Grid hasGutter>
          <GridItem span={12} lg={4}>
            <LookupQueryDirectoryCard
              form={form}
              isRunning={isRunning}
              history={history}
              selectedEntry={selectedEntry}
              onSelectHistoryId={setSelectedHistoryId}
              onSubmit={onSubmit}
            />
          </GridItem>

          <GridItem span={12} lg={8}>
            <LookupResultDetailCard result={result} selectedEntry={selectedEntry} />
          </GridItem>
        </Grid>
      </PageSection>
    </>
  );
}
