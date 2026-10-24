import React from 'react';
import {
  Button,
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
  Flex,
  FlexItem,
  Label
} from '@patternfly/react-core';
import { formatHumanTtl } from '../../../utils';
import type { DnsZoneView } from '../types/dnsRecords.types';

export interface ZoneContextHeaderCardProps {
  readonly activeZone: DnsZoneView;
  readonly isReadOnly: boolean;
  readonly onExportZoneBind: (zone: DnsZoneView) => Promise<void>;
  readonly onEditZone: (zone: DnsZoneView) => void;
  readonly onDeleteZone: (zone: DnsZoneView) => void;
}

export function ZoneContextHeaderCard({
  activeZone,
  isReadOnly,
  onExportZoneBind,
  onEditZone,
  onDeleteZone
}: ZoneContextHeaderCardProps): React.JSX.Element {
  return (
    <Card isCompact>
      <CardHeader>
        <Flex
          justifyContent={{ default: 'justifyContentSpaceBetween' }}
          alignItems={{ default: 'alignItemsCenter' }}
          gap={{ default: 'gapSm' }}
        >
          <FlexItem>
            <Flex alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapSm' }}>
              <FlexItem>
                <CardTitle>Zone: {activeZone.name}</CardTitle>
              </FlexItem>
              <FlexItem>
                <Label isCompact color={activeZone.mode === 'authoritative' ? 'purple' : 'teal'}>
                  {activeZone.mode === 'authoritative'
                    ? 'Authoritative Zone (NXDOMAIN for missing subdomains)'
                    : 'Split-Horizon Override Zone (Upstream Fallback)'}
                </Label>
              </FlexItem>
              <FlexItem>
                <Label isCompact color={activeZone.enabled ? 'green' : 'grey'}>
                  {activeZone.enabled ? 'Active' : 'Disabled'}
                </Label>
              </FlexItem>
            </Flex>
          </FlexItem>
          <FlexItem>
            <Flex gap={{ default: 'gapSm' }}>
              <FlexItem>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => void onExportZoneBind(activeZone)}
                >
                  Export BIND File
                </Button>
              </FlexItem>
              {!isReadOnly && (
                <>
                  <FlexItem>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => { onEditZone(activeZone); }}
                    >
                      Edit SOA / Zone
                    </Button>
                  </FlexItem>
                  <FlexItem>
                    <Button variant="danger" size="sm" onClick={() => { onDeleteZone(activeZone); }}>
                      Delete Zone
                    </Button>
                  </FlexItem>
                </>
              )}
            </Flex>
          </FlexItem>
        </Flex>
      </CardHeader>
      <CardBody>
        <DescriptionList isCompact isHorizontal columnModifier={{ default: '3Col' }}>
          <DescriptionListGroup>
            <DescriptionListTerm>SOA Serial</DescriptionListTerm>
            <DescriptionListDescription>
              <code>{activeZone.serial}</code>
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Primary NS (MNAME)</DescriptionListTerm>
            <DescriptionListDescription>
              <code>{activeZone.primary_ns}.</code>
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Responsible Mailbox (RNAME)</DescriptionListTerm>
            <DescriptionListDescription>
              <code>{activeZone.admin_email}.</code>
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Default Zone TTL</DescriptionListTerm>
            <DescriptionListDescription>
              {formatHumanTtl(activeZone.default_ttl)}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>SOA Timers (Refresh / Retry)</DescriptionListTerm>
            <DescriptionListDescription>
              {activeZone.refresh}s / {activeZone.retry}s
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>SOA Expiry / Neg-Cache TTL</DescriptionListTerm>
            <DescriptionListDescription>
              {activeZone.expire}s / {activeZone.minimum}s
            </DescriptionListDescription>
          </DescriptionListGroup>
        </DescriptionList>
        {activeZone.comment && (
          <Content component={ContentVariants.small} className="pf-v6-u-mt-xs">
            Note: {activeZone.comment}
          </Content>
        )}
      </CardBody>
    </Card>
  );
}
