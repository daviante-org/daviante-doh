import React from 'react';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Content,
  DataList,
  DataListCell,
  DataListItem,
  DataListItemCells,
  DataListItemRow,
  Divider,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  Flex,
  FlexItem,
  FormSelect,
  FormSelectOption,
  FormSelectOptionGroup,
  Label,
  Pagination,
  SearchInput,
  Spinner,
  Stack,
  StackItem,
  ToggleGroup,
  ToggleGroupItem
} from '@patternfly/react-core';
import {
  BanIcon,
  CheckCircleIcon,
  DatabaseIcon,
  GlobeAmericasIcon,
  LockIcon,
  PlusCircleIcon,
  SearchIcon,
  ShieldAltIcon
} from '@patternfly/react-icons';
import { PER_PAGE_OPTIONS, RECORD_TYPE_GROUPS } from '../../../constants';
import type { DnsDirectoryMode } from '../hooks/useDnsRecordsWorkspace';
import type { DnsZoneView, LocalDnsRecordView } from '../types/dnsRecords.types';
import {
  formatRecordValueSummary,
  getRecordTypeColor
} from '../utils/recordFormatters';

export interface RecordDirectoryCardProps {
  readonly directoryMode: DnsDirectoryMode;
  readonly isLoading: boolean;
  readonly isReadOnly: boolean;
  readonly zones: readonly DnsZoneView[];
  readonly filteredZones: readonly DnsZoneView[];
  readonly selectedZoneKey: string;
  readonly selectedZone: DnsZoneView | null;
  readonly zoneSearchInput: string;
  readonly visibleRecords: readonly LocalDnsRecordView[];
  readonly selectedRecord: LocalDnsRecordView | null;
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
  readonly searchInput: string;
  readonly filterRecordType: string;
  readonly filterEnabled: 'all' | 'enabled' | 'disabled';
  readonly onChangeDirectoryMode: (mode: DnsDirectoryMode) => void;
  readonly onSelectRecord: (recordId: string) => void;
  readonly onSelectZoneKey: (zoneKey: string) => void;
  readonly onSearchChange: (value: string) => void;
  readonly onZoneSearchChange: (value: string) => void;
  readonly onRecordTypeChange: (value: string) => void;
  readonly onEnabledFilterChange: (value: 'all' | 'enabled' | 'disabled') => void;
  readonly onClearFilters: () => void;
  readonly onPageChange: (newPage: number) => void;
  readonly onPerPageChange: (newPerPage: number) => void;
  readonly onOpenCreateRecordModal: () => void;
  readonly onOpenCreateZoneModal: () => void;
}

export function RecordDirectoryCard({
  directoryMode,
  isLoading,
  isReadOnly,
  zones,
  filteredZones,
  selectedZoneKey,
  selectedZone,
  zoneSearchInput,
  visibleRecords,
  selectedRecord,
  total,
  page,
  perPage,
  searchInput,
  filterRecordType,
  filterEnabled,
  onChangeDirectoryMode,
  onSelectRecord,
  onSelectZoneKey,
  onSearchChange,
  onZoneSearchChange,
  onRecordTypeChange,
  onEnabledFilterChange,
  onClearFilters,
  onPageChange,
  onPerPageChange,
  onOpenCreateRecordModal,
  onOpenCreateZoneModal
}: RecordDirectoryCardProps): React.JSX.Element {
  const hasActiveRecordFilters =
    searchInput.trim().length > 0 ||
    selectedZoneKey !== 'ALL' ||
    filterRecordType.length > 0 ||
    filterEnabled !== 'all';

  return (
    <Card isFullHeight>
      <CardHeader>
        <Flex
          justifyContent={{ default: 'justifyContentSpaceBetween' }}
          alignItems={{ default: 'alignItemsCenter' }}
          gap={{ default: 'gapSm' }}
        >
          <FlexItem>
            <CardTitle>
              <Flex
                spaceItems={{ default: 'spaceItemsSm' }}
                alignItems={{ default: 'alignItemsCenter' }}
              >
                <FlexItem>
                  <ToggleGroup isCompact aria-label="Switch between DNS records and zones directory">
                    <ToggleGroupItem
                      text={`Records (${String(total)})`}
                      buttonId="directory-mode-records"
                      isSelected={directoryMode === 'records'}
                      onChange={() => {
                        onChangeDirectoryMode('records');
                      }}
                    />
                    <ToggleGroupItem
                      text={`Zones (${String(zones.length)})`}
                      buttonId="directory-mode-zones"
                      isSelected={directoryMode === 'zones'}
                      onChange={() => {
                        onChangeDirectoryMode('zones');
                      }}
                    />
                  </ToggleGroup>
                </FlexItem>
              </Flex>
            </CardTitle>
          </FlexItem>

          {!isReadOnly && (
            <FlexItem>
              {directoryMode === 'records' ? (
                <Button
                  variant="primary"
                  size="sm"
                  icon={<PlusCircleIcon />}
                  onClick={onOpenCreateRecordModal}
                >
                  Create record
                </Button>
              ) : (
                <Button
                  variant="primary"
                  size="sm"
                  icon={<PlusCircleIcon />}
                  onClick={onOpenCreateZoneModal}
                >
                  Create zone
                </Button>
              )}
            </FlexItem>
          )}
        </Flex>
      </CardHeader>

      <Divider />

      <CardBody isFilled>
        {directoryMode === 'records' ? (
          <Stack hasGutter>
            <StackItem>
              <SearchInput
                placeholder="Filter records by domain, IP/target, or comment..."
                value={searchInput}
                onChange={(_event, val) => {
                  onSearchChange(val);
                  onPageChange(1);
                }}
                onClear={() => {
                  onSearchChange('');
                  onPageChange(1);
                }}
                aria-label="Search local DNS records"
              />
            </StackItem>

            <StackItem>
              <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                <FlexItem flex={{ default: 'flex_1' }} style={{ minWidth: '125px' }}>
                  <FormSelect
                    value={selectedZoneKey}
                    onChange={(_event, val) => {
                      onSelectZoneKey(val);
                      onPageChange(1);
                    }}
                    aria-label="Filter by authoritative zone"
                  >
                    <FormSelectOption value="ALL" label="All zones" />
                    <FormSelectOption value="UNZONED" label="Global overrides (unzoned)" />
                    {zones.map((z) => (
                      <FormSelectOption
                        key={z.id}
                        value={z.id}
                        label={`${z.name} (${String(z.record_count)})`}
                      />
                    ))}
                  </FormSelect>
                </FlexItem>

                <FlexItem flex={{ default: 'flex_1' }} style={{ minWidth: '125px' }}>
                  <FormSelect
                    value={filterRecordType}
                    onChange={(_event, val) => {
                      onRecordTypeChange(val);
                    }}
                    aria-label="Filter by DNS RR type"
                  >
                    <FormSelectOption value="" label="All RR types" />
                    {RECORD_TYPE_GROUPS.map((grp) => (
                      <FormSelectOptionGroup key={grp.label} label={grp.label}>
                        {grp.types.map((t) => (
                          <FormSelectOption key={t.value} value={t.value} label={t.value} />
                        ))}
                      </FormSelectOptionGroup>
                    ))}
                  </FormSelect>
                </FlexItem>

                <FlexItem flex={{ default: 'flex_1' }} style={{ minWidth: '115px' }}>
                  <FormSelect
                    value={filterEnabled}
                    onChange={(_event, val) => {
                      onEnabledFilterChange(val as 'all' | 'enabled' | 'disabled');
                      onPageChange(1);
                    }}
                    aria-label="Filter by record status"
                  >
                    <FormSelectOption value="all" label="All statuses" />
                    <FormSelectOption value="enabled" label="Active only" />
                    <FormSelectOption value="disabled" label="Disabled only" />
                  </FormSelect>
                </FlexItem>

                {hasActiveRecordFilters && (
                  <FlexItem>
                    <Button variant="link" size="sm" isInline onClick={onClearFilters}>
                      Reset filters
                    </Button>
                  </FlexItem>
                )}
              </Flex>
            </StackItem>

            <StackItem>
              {isLoading ? (
                <EmptyState
                  variant="sm"
                  titleText="Loading DNS records"
                  headingLevel="h3"
                  icon={Spinner}
                />
              ) : visibleRecords.length === 0 ? (
                <EmptyState
                  variant="sm"
                  titleText={
                    hasActiveRecordFilters
                      ? 'No matching DNS records'
                      : 'No local DNS records found'
                  }
                  headingLevel="h3"
                  icon={hasActiveRecordFilters ? SearchIcon : DatabaseIcon}
                >
                  <EmptyStateBody>
                    {hasActiveRecordFilters
                      ? 'No DNS records matched your current search or filter criteria.'
                      : 'Create your first authoritative or split-horizon DNS record to begin serving local answers.'}
                  </EmptyStateBody>
                  <EmptyStateFooter>
                    <EmptyStateActions>
                      {hasActiveRecordFilters ? (
                        <Button variant="link" onClick={onClearFilters}>
                          Reset filters
                        </Button>
                      ) : !isReadOnly ? (
                        <Button
                          variant="primary"
                          icon={<PlusCircleIcon />}
                          onClick={onOpenCreateRecordModal}
                        >
                          Create record
                        </Button>
                      ) : null}
                    </EmptyStateActions>
                  </EmptyStateFooter>
                </EmptyState>
              ) : (
                <DataList
                  aria-label="Local DNS records directory"
                  isCompact
                  selectedDataListItemId={selectedRecord?.id ?? ''}
                  onSelectDataListItem={(_event, id) => {
                    onSelectRecord(id);
                  }}
                >
                  {visibleRecords.map((item) => {
                    const valSummary = formatRecordValueSummary(item.record);
                    const typeColor = getRecordTypeColor(item.record.type);

                    return (
                      <DataListItem
                        key={item.id}
                        id={item.id}
                        aria-labelledby={`dns-record-item-${item.id}`}
                      >
                        <DataListItemRow>
                          <DataListItemCells
                            dataListCells={[
                              <DataListCell key="primary" isFilled>
                                <Flex
                                  direction={{ default: 'column' }}
                                  flexWrap={{ default: 'nowrap' }}
                                  spaceItems={{ default: 'spaceItemsXs' }}
                                >
                                  <FlexItem>
                                    <Flex
                                      justifyContent={{
                                        default: 'justifyContentSpaceBetween'
                                      }}
                                      alignItems={{ default: 'alignItemsCenter' }}
                                      gap={{ default: 'gapSm' }}
                                    >
                                      <FlexItem>
                                        <Flex
                                          gap={{ default: 'gapXs' }}
                                          alignItems={{ default: 'alignItemsCenter' }}
                                        >
                                          <FlexItem>
                                            <span id={`dns-record-item-${item.id}`}>
                                              <strong className="pf-v6-u-font-family-monospace">
                                                {item.domain}
                                              </strong>
                                            </span>
                                          </FlexItem>
                                          {valSummary.badge !== undefined && (
                                            <FlexItem>
                                              <Label color="teal" isCompact>
                                                {valSummary.badge}
                                              </Label>
                                            </FlexItem>
                                          )}
                                        </Flex>
                                      </FlexItem>

                                      <FlexItem>
                                        {item.enabled ? (
                                          <Label
                                            color="green"
                                            isCompact
                                            icon={<CheckCircleIcon />}
                                          >
                                            Active
                                          </Label>
                                        ) : (
                                          <Label color="grey" isCompact icon={<BanIcon />}>
                                            Disabled
                                          </Label>
                                        )}
                                      </FlexItem>
                                    </Flex>
                                  </FlexItem>

                                  <FlexItem>
                                    <Content component="small">
                                      <code>{valSummary.primary}</code> &bull; TTL{' '}
                                      {String(item.ttl)}s
                                      {item.comment ? ` • ${item.comment}` : ''}
                                    </Content>
                                  </FlexItem>

                                  <FlexItem>
                                    <Flex
                                      gap={{ default: 'gapSm' }}
                                      alignItems={{ default: 'alignItemsCenter' }}
                                    >
                                      <FlexItem>
                                        <Label
                                          color={typeColor}
                                          isCompact
                                          icon={<ShieldAltIcon />}
                                        >
                                          {item.record.type} (TYPE{String(item.rr_type_code)})
                                        </Label>
                                      </FlexItem>
                                      <FlexItem>
                                        <Label
                                          color={item.zone_name ? 'purple' : 'grey'}
                                          isCompact
                                          variant="outline"
                                        >
                                          {item.zone_name ?? 'Global override'}
                                        </Label>
                                      </FlexItem>
                                    </Flex>
                                  </FlexItem>
                                </Flex>
                              </DataListCell>
                            ]}
                          />
                        </DataListItemRow>
                      </DataListItem>
                    );
                  })}
                </DataList>
              )}
            </StackItem>

            {total > perPage && (
              <StackItem>
                <Divider />
                <Pagination
                  itemCount={total}
                  perPage={perPage}
                  page={page}
                  perPageOptions={[...PER_PAGE_OPTIONS]}
                  onSetPage={(_event, newPage) => {
                    onPageChange(newPage);
                  }}
                  onPerPageSelect={(_event, newPerPage) => {
                    onPerPageChange(newPerPage);
                    onPageChange(1);
                  }}
                  variant="bottom"
                  isCompact
                  isStatic
                  titles={{
                    paginationAriaLabel: 'Local DNS records directory pagination'
                  }}
                />
              </StackItem>
            )}
          </Stack>
        ) : (
          <Stack hasGutter>
            <StackItem>
              <SearchInput
                placeholder="Filter zones by apex domain or comment..."
                value={zoneSearchInput}
                onChange={(_event, val) => {
                  onZoneSearchChange(val);
                }}
                onClear={() => {
                  onZoneSearchChange('');
                }}
                aria-label="Search authoritative DNS zones"
              />
            </StackItem>

            <StackItem>
              {filteredZones.length === 0 ? (
                <EmptyState
                  variant="sm"
                  titleText="No DNS zones found"
                  headingLevel="h3"
                  icon={GlobeAmericasIcon}
                >
                  <EmptyStateBody>
                    Create an authoritative or split-horizon DNS zone to configure SOA timers,
                    NXDOMAIN synthesis, and RFC 1035 BIND exports.
                  </EmptyStateBody>
                  {!isReadOnly && (
                    <EmptyStateFooter>
                      <EmptyStateActions>
                        <Button
                          variant="primary"
                          icon={<PlusCircleIcon />}
                          onClick={onOpenCreateZoneModal}
                        >
                          Create zone
                        </Button>
                      </EmptyStateActions>
                    </EmptyStateFooter>
                  )}
                </EmptyState>
              ) : (
                <DataList
                  aria-label="Authoritative DNS zones directory"
                  isCompact
                  selectedDataListItemId={selectedZone?.id ?? ''}
                  onSelectDataListItem={(_event, id) => {
                    onSelectZoneKey(id);
                  }}
                >
                  {filteredZones.map((zone) => (
                    <DataListItem
                      key={zone.id}
                      id={zone.id}
                      aria-labelledby={`dns-zone-item-${zone.id}`}
                    >
                      <DataListItemRow>
                        <DataListItemCells
                          dataListCells={[
                            <DataListCell key="primary" isFilled>
                              <Flex
                                direction={{ default: 'column' }}
                                flexWrap={{ default: 'nowrap' }}
                                spaceItems={{ default: 'spaceItemsXs' }}
                              >
                                <FlexItem>
                                  <Flex
                                    justifyContent={{
                                      default: 'justifyContentSpaceBetween'
                                    }}
                                    alignItems={{ default: 'alignItemsCenter' }}
                                    gap={{ default: 'gapSm' }}
                                  >
                                    <FlexItem>
                                      <Flex
                                        gap={{ default: 'gapXs' }}
                                        alignItems={{ default: 'alignItemsCenter' }}
                                      >
                                        <FlexItem>
                                          <span id={`dns-zone-item-${zone.id}`}>
                                            <strong className="pf-v6-u-font-family-monospace">
                                              {zone.name}
                                            </strong>
                                          </span>
                                        </FlexItem>
                                        <FlexItem>
                                          <Badge isRead>{zone.record_count}</Badge>
                                        </FlexItem>
                                      </Flex>
                                    </FlexItem>
                                    <FlexItem>
                                      {zone.enabled ? (
                                        <Label
                                          color="green"
                                          isCompact
                                          icon={<CheckCircleIcon />}
                                        >
                                          Active
                                        </Label>
                                      ) : (
                                        <Label color="grey" isCompact icon={<BanIcon />}>
                                          Disabled
                                        </Label>
                                      )}
                                    </FlexItem>
                                  </Flex>
                                </FlexItem>

                                <FlexItem>
                                  <Content component="small">
                                    MNAME: <code>{zone.primary_ns}</code> &bull; Serial{' '}
                                    <code>{String(zone.serial)}</code>
                                    {zone.comment ? ` • ${zone.comment}` : ''}
                                  </Content>
                                </FlexItem>

                                <FlexItem>
                                  <Flex
                                    gap={{ default: 'gapSm' }}
                                    alignItems={{ default: 'alignItemsCenter' }}
                                  >
                                    <FlexItem>
                                      <Label
                                        color={
                                          zone.mode === 'authoritative' ? 'blue' : 'purple'
                                        }
                                        isCompact
                                        icon={<LockIcon />}
                                      >
                                        {zone.mode === 'authoritative'
                                          ? 'Authoritative (AA=1)'
                                          : 'Split-Horizon'}
                                      </Label>
                                    </FlexItem>
                                    <FlexItem>
                                      <Label color="grey" isCompact variant="outline">
                                        Default TTL {String(zone.default_ttl)}s
                                      </Label>
                                    </FlexItem>
                                  </Flex>
                                </FlexItem>
                              </Flex>
                            </DataListCell>
                          ]}
                        />
                      </DataListItemRow>
                    </DataListItem>
                  ))}
                </DataList>
              )}
            </StackItem>
          </Stack>
        )}
      </CardBody>
    </Card>
  );
}
