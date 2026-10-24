import React from 'react';
import {
  Alert,
  Content,
  ContentVariants,
  PageSection,
  Stack,
  StackItem
} from '@patternfly/react-core';
import { useDnsLookup } from '../hooks/useDnsLookup';
import { LookupJsonPayloadCard } from './LookupJsonPayloadCard';
import { LookupQueryFormCard } from './LookupQueryFormCard';
import { LookupResultSummaryCard } from './LookupResultSummaryCard';

export function DnsLookupTesterFeature(): React.JSX.Element {
  const { form, result, lookupError, isRunning, onSubmit } = useDnsLookup();

  return (
    <PageSection isFilled>
      <Stack hasGutter>
        <StackItem>
          <Content component={ContentVariants.h1}>Live DNS Lookup &amp; Policy Tester</Content>
          <Content component={ContentVariants.p}>
            Test domain resolution directly against the DoH server pipeline (Protective DNS Policy
            → Local Overrides / CNAME Chain → Upstream Pool + DNS Rebinding Guard).
          </Content>
        </StackItem>

        {lookupError !== null && (
          <StackItem>
            <Alert variant="danger" isInline title={lookupError} />
          </StackItem>
        )}

        <StackItem>
          <LookupQueryFormCard form={form} isRunning={isRunning} onSubmit={onSubmit} />
        </StackItem>

        {result !== null && (
          <>
            <StackItem>
              <LookupResultSummaryCard result={result} />
            </StackItem>
            <StackItem>
              <LookupJsonPayloadCard result={result} />
            </StackItem>
          </>
        )}
      </Stack>
    </PageSection>
  );
}
