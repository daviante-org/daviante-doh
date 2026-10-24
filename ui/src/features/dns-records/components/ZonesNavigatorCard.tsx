import React from 'react';
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  DataList,
  DataListCell,
  DataListItem,
  DataListItemCells,
  DataListItemRow,
  Flex,
  FlexItem,
  Label,
  SearchInput,
  Stack,
  StackItem
} from '@patternfly/react-core';
import type { DnsZoneView } from '../types/dnsRecords.types';

export interface ZonesNavigatorCardProps {
  readonly zones: readonly DnsZoneView[];
  readonly filteredZones: readonly DnsZoneView[];
  readonly selectedZoneKey: string;
  readonly zoneSearchInput: string;
  readonly isReadOnly: boolean;
  readonly onSelectZoneKey: (key: string) => void;
  readonly onZoneSearchChange: (val: string) => void;
  readonly onOpenCreateZone: () => void;
}

export function ZonesNavigatorCard({
  zones,
  filteredZones,
  selectedZoneKey,
  zoneSearchInput,
  isReadOnly,
  onSelectZoneKey,
  onZoneSearchChange,
  onOpenCreateZone
}: ZonesNavigatorCardProps): React.JSX.Element {
  return (
    <Card isFullHeight>
      <CardHeader>
        <Flex
          justifyContent={{ default: 'justifyContentSpaceBetween' }}
          alignItems={{ default: 'alignItemsCenter' }}
          gap={{ default: 'gapSm' }}
        >
          <FlexItem>
            <CardTitle>DNS Zones ({zones.length})</CardTitle>
          </FlexItem>
          {!isReadOnly && (
            <FlexItem>
              <Button variant="secondary" size="sm" onClick={onOpenCreateZone}>
                + New Zone
              </Button>
            </FlexItem>
          )}
        </Flex>
      </CardHeader>
      <CardBody isFilled>
        <Stack hasGutter>
          <StackItem>
            <SearchInput
              aria-label="Filter DNS zones"
              placeholder="Find zone..."
              value={zoneSearchInput}
              onChange={(_e, val) => { onZoneSearchChange(val); }}
              onClear={() => { onZoneSearchChange(''); }}
            />
          </StackItem>
          <StackItem isFilled>
            <DataList
              aria-label="DNS Zones Navigation List"
              isCompact
              selectedDataListItemId={selectedZoneKey}
              onSelectDataListItem={(_e, id) => { onSelectZoneKey(id); }}
            >
              <DataListItem id="ALL" aria-labelledby="zone-item-all">
                <DataListItemRow>
                  <DataListItemCells
                    dataListCells={[
                      <DataListCell key="primary">
                        <span id="zone-item-all">
                          <strong>All DNS Records</strong>
                        </span>
                        <div>
                          <small>Global &amp; Zoned Overrides</small>
                        </div>
                      </DataListCell>
                    ]}
                  />
                </DataListItemRow>
              </DataListItem>

              <DataListItem id="UNZONED" aria-labelledby="zone-item-unzoned">
                <DataListItemRow>
                  <DataListItemCells
                    dataListCells={[
                      <DataListCell key="primary">
                        <span id="zone-item-unzoned">
                          <strong>Unzoned (Global Overrides)</strong>
                        </span>
                        <div>
                          <small>Standalone FQDNs</small>
                        </div>
                      </DataListCell>
                    ]}
                  />
                </DataListItemRow>
              </DataListItem>

              {filteredZones.map((zone) => (
                <DataListItem key={zone.id} id={zone.id} aria-labelledby={`zone-item-${zone.id}`}>
                  <DataListItemRow>
                    <DataListItemCells
                      dataListCells={[
                        <DataListCell key="primary">
                          <Flex
                            justifyContent={{ default: 'justifyContentSpaceBetween' }}
                            alignItems={{ default: 'alignItemsCenter' }}
                            gap={{ default: 'gapXs' }}
                          >
                            <FlexItem>
                              <span id={`zone-item-${zone.id}`}>
                                <strong>{zone.name}</strong>
                              </span>
                            </FlexItem>
                            <FlexItem>
                              <Label isCompact color={zone.enabled ? 'blue' : 'grey'}>
                                {zone.record_count}
                              </Label>
                            </FlexItem>
                          </Flex>
                          <Flex gap={{ default: 'gapXs' }} className="pf-v6-u-mt-xs">
                            <FlexItem>
                              <Label
                                isCompact
                                color={zone.mode === 'authoritative' ? 'purple' : 'teal'}
                              >
                                {zone.mode === 'authoritative' ? 'Authoritative' : 'Split-Horizon'}
                              </Label>
                            </FlexItem>
                            {!zone.enabled && (
                              <FlexItem>
                                <Label isCompact color="orange">
                                  Disabled
                                </Label>
                              </FlexItem>
                            )}
                          </Flex>
                        </DataListCell>
                      ]}
                    />
                  </DataListItemRow>
                </DataListItem>
              ))}
            </DataList>
          </StackItem>
        </Stack>
      </CardBody>
    </Card>
  );
}
