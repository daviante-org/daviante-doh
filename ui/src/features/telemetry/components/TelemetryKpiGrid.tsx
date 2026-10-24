import React from 'react';
import {
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Content,
  ContentVariants,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Grid,
  GridItem
} from '@patternfly/react-core';
import type { TelemetrySummaryResponse } from '../types/telemetry.types';

export interface TelemetryKpiGridProps {
  readonly summary: TelemetrySummaryResponse;
}

export function TelemetryKpiGrid({ summary }: TelemetryKpiGridProps): React.JSX.Element {
  return (
    <Grid hasGutter>
      <GridItem md={3} sm={6}>
        <Card isFullHeight>
          <CardHeader>
            <CardTitle>Total Queries</CardTitle>
          </CardHeader>
          <CardBody>
            <Content component={ContentVariants.h2}>
              {summary.total_queries.toLocaleString()}
            </Content>
            <DescriptionList isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Rate-Limited</DescriptionListTerm>
                <DescriptionListDescription>
                  {summary.rate_limited_queries.toLocaleString()}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </GridItem>

      <GridItem md={3} sm={6}>
        <Card isFullHeight>
          <CardHeader>
            <CardTitle>Cache Hit Ratio</CardTitle>
          </CardHeader>
          <CardBody>
            <Content component={ContentVariants.h2}>
              {summary.cache_hit_ratio_percent.toFixed(1)}%
            </Content>
            <DescriptionList isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Hits / Misses</DescriptionListTerm>
                <DescriptionListDescription>
                  {summary.cache_hits.toLocaleString()} / {summary.cache_misses.toLocaleString()}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </GridItem>

      <GridItem md={3} sm={6}>
        <Card isFullHeight>
          <CardHeader>
            <CardTitle>Local Overrides</CardTitle>
          </CardHeader>
          <CardBody>
            <Content component={ContentVariants.h2}>
              {summary.local_overrides.toLocaleString()}
            </Content>
            <DescriptionList isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Active Records</DescriptionListTerm>
                <DescriptionListDescription>
                  {summary.active_local_records.toLocaleString()}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </GridItem>

      <GridItem md={3} sm={6}>
        <Card isFullHeight>
          <CardHeader>
            <CardTitle>Policy &amp; Rebinding Blocks</CardTitle>
          </CardHeader>
          <CardBody>
            <Content component={ContentVariants.h2}>
              {(summary.policy_blocks + summary.rebinding_blocks).toLocaleString()}
            </Content>
            <DescriptionList isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Policy / Rebinding</DescriptionListTerm>
                <DescriptionListDescription>
                  {summary.policy_blocks.toLocaleString()} /{' '}
                  {summary.rebinding_blocks.toLocaleString()}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </GridItem>
    </Grid>
  );
}
