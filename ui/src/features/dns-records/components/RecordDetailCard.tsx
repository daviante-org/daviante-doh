import React from 'react';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  ClipboardCopy,
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
  Form,
  FormGroup,
  Grid,
  GridItem,
  Label,
  Stack,
  StackItem,
  TextInput
} from '@patternfly/react-core';
import {
  BanIcon,
  CheckCircleIcon,
  CopyIcon,
  DatabaseIcon,
  DownloadIcon,
  GlobeAmericasIcon,
  LockIcon,
  PencilAltIcon,
  ShieldAltIcon,
  TrashIcon,
  UndoIcon
} from '@patternfly/react-icons';
import { formatUpdatedEpoch } from '../../../utils';
import type { DnsDirectoryMode } from '../hooks/useDnsRecordsWorkspace';
import type { DnsZoneView, LocalDnsRecordView } from '../types/dnsRecords.types';
import {
  formatRecordValueSummary,
  getRecordRdataBreakdown,
  getRecordTypeColor
} from '../utils/recordFormatters';

export interface RecordDetailCardProps {
  readonly directoryMode: DnsDirectoryMode;
  readonly isReadOnly: boolean;
  readonly selectedRecord: LocalDnsRecordView | null;
  readonly selectedZone: DnsZoneView | null;
  readonly zones: readonly DnsZoneView[];
  readonly onOpenEditRecord: (record: LocalDnsRecordView) => void;
  readonly onOpenCloneRecord: (record: LocalDnsRecordView) => void;
  readonly onQuickToggleEnabled: (record: LocalDnsRecordView) => Promise<void>;
  readonly onOpenDeleteRecord: (record: LocalDnsRecordView) => void;
  readonly onOpenEditZone: (zone: DnsZoneView) => void;
  readonly onExportZoneBind: (zone: DnsZoneView) => Promise<void>;
  readonly onOpenDeleteZone: (zone: DnsZoneView) => void;
  readonly onFilterRecordsByZone: (zoneId: string) => void;
}

export function RecordDetailCard({
  directoryMode,
  isReadOnly,
  selectedRecord,
  selectedZone,
  zones,
  onOpenEditRecord,
  onOpenCloneRecord,
  onQuickToggleEnabled,
  onOpenDeleteRecord,
  onOpenEditZone,
  onExportZoneBind,
  onOpenDeleteZone,
  onFilterRecordsByZone
}: RecordDetailCardProps): React.JSX.Element {
  if (directoryMode === 'zones') {
    if (!selectedZone) {
      return (
        <Card isFullHeight>
          <CardBody isFilled>
            <EmptyState
              variant="lg"
              titleText="Select an authoritative DNS zone"
              headingLevel="h2"
              icon={GlobeAmericasIcon}
            >
              <EmptyStateBody>
                Choose a DNS zone from the directory on the left to inspect its RFC 1035 Start of
                Authority (SOA) timers, resolution mode, and BIND export controls.
              </EmptyStateBody>
            </EmptyState>
          </CardBody>
        </Card>
      );
    }

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
                    {selectedZone.name}
                  </CardTitle>
                </FlexItem>
                <FlexItem>
                  <Label
                    color={selectedZone.mode === 'authoritative' ? 'blue' : 'purple'}
                    icon={<LockIcon />}
                  >
                    {selectedZone.mode === 'authoritative'
                      ? 'Authoritative (AA=1)'
                      : 'Split-Horizon Override'}
                  </Label>
                </FlexItem>
                <FlexItem>
                  {selectedZone.enabled ? (
                    <Label color="green" icon={<CheckCircleIcon />}>
                      Active
                    </Label>
                  ) : (
                    <Label color="grey" icon={<BanIcon />}>
                      Disabled
                    </Label>
                  )}
                </FlexItem>
              </Flex>
            </FlexItem>

            <FlexItem>
              <Content component="p">
                MNAME: <code>{selectedZone.primary_ns}</code> &bull; RNAME:{' '}
                <code>{selectedZone.admin_email}</code>
                {selectedZone.comment ? ` • ${selectedZone.comment}` : ''}
              </Content>
            </FlexItem>

            <FlexItem>
              <Content component="small">
                SOA Serial <code>{String(selectedZone.serial)}</code> &bull; Last updated{' '}
                {formatUpdatedEpoch(selectedZone.updated_at_epoch)} &bull;{' '}
                {String(selectedZone.record_count)} configured record(s)
              </Content>
            </FlexItem>
          </Flex>
        </CardHeader>

        <Divider />

        <CardBody isFilled>
          <Stack hasGutter>
            <StackItem>
              <Card isCompact variant="secondary">
                <CardHeader>
                  <Flex
                    justifyContent={{ default: 'justifyContentSpaceBetween' }}
                    alignItems={{ default: 'alignItemsCenter' }}
                    gap={{ default: 'gapSm' }}
                  >
                    <FlexItem>
                      <strong>Start of Authority (SOA) &amp; Zone Timers</strong>
                    </FlexItem>
                    {!isReadOnly && (
                      <FlexItem>
                        <Button
                          variant="secondary"
                          size="sm"
                          icon={<PencilAltIcon />}
                          onClick={() => {
                            onOpenEditZone(selectedZone);
                          }}
                        >
                          Edit details
                        </Button>
                      </FlexItem>
                    )}
                  </Flex>
                </CardHeader>

                <Divider />

                <CardBody>
                  <Form>
                    <Grid hasGutter>
                      <GridItem span={12} md={6}>
                        <FormGroup label="Zone apex domain" fieldId="zone-detail-name">
                          <TextInput
                            id="zone-detail-name"
                            value={selectedZone.name}
                            isDisabled
                            aria-label="Zone apex domain"
                          />
                        </FormGroup>
                      </GridItem>
                      <GridItem span={12} md={6}>
                        <FormGroup label="Resolution mode" fieldId="zone-detail-mode">
                          <TextInput
                            id="zone-detail-mode"
                            value={
                              selectedZone.mode === 'authoritative'
                                ? 'Authoritative (AA=1 + NXDOMAIN/NODATA)'
                                : 'Split-Horizon Override (Fallback to Upstream)'
                            }
                            isDisabled
                            aria-label="Zone resolution mode"
                          />
                        </FormGroup>
                      </GridItem>
                      <GridItem span={12} md={6}>
                        <FormGroup
                          label="Primary nameserver (MNAME)"
                          fieldId="zone-detail-mname"
                        >
                          <TextInput
                            id="zone-detail-mname"
                            value={selectedZone.primary_ns}
                            isDisabled
                            aria-label="Primary nameserver"
                          />
                        </FormGroup>
                      </GridItem>
                      <GridItem span={12} md={6}>
                        <FormGroup
                          label="Responsible mailbox (RNAME)"
                          fieldId="zone-detail-rname"
                        >
                          <TextInput
                            id="zone-detail-rname"
                            value={selectedZone.admin_email}
                            isDisabled
                            aria-label="Responsible mailbox"
                          />
                        </FormGroup>
                      </GridItem>
                      <GridItem span={12} md={4}>
                        <FormGroup label="SOA Serial" fieldId="zone-detail-serial">
                          <TextInput
                            id="zone-detail-serial"
                            value={String(selectedZone.serial)}
                            isDisabled
                            aria-label="SOA serial"
                          />
                        </FormGroup>
                      </GridItem>
                      <GridItem span={12} md={4}>
                        <FormGroup
                          label="Refresh / Retry / Expire"
                          fieldId="zone-detail-timers"
                        >
                          <TextInput
                            id="zone-detail-timers"
                            value={`${String(selectedZone.refresh)}s / ${String(selectedZone.retry)}s / ${String(selectedZone.expire)}s`}
                            isDisabled
                            aria-label="SOA timers"
                          />
                        </FormGroup>
                      </GridItem>
                      <GridItem span={12} md={4}>
                        <FormGroup
                          label="Negative TTL / Default TTL"
                          fieldId="zone-detail-minimum"
                        >
                          <TextInput
                            id="zone-detail-minimum"
                            value={`${String(selectedZone.minimum)}s / ${String(selectedZone.default_ttl)}s`}
                            isDisabled
                            aria-label="Negative caching and default TTL"
                          />
                        </FormGroup>
                      </GridItem>
                    </Grid>
                  </Form>
                </CardBody>
              </Card>
            </StackItem>

            <StackItem>
              <Card isCompact variant="secondary">
                <CardHeader>
                  <Flex
                    justifyContent={{ default: 'justifyContentSpaceBetween' }}
                    alignItems={{ default: 'alignItemsCenter' }}
                    gap={{ default: 'gapSm' }}
                  >
                    <FlexItem>
                      <strong>Zone Lifecycle &amp; RFC 1035 BIND Controls</strong>
                    </FlexItem>
                    <FlexItem>
                      <Badge isRead={selectedZone.record_count === 0}>
                        {String(selectedZone.record_count)} record(s)
                      </Badge>
                    </FlexItem>
                  </Flex>
                </CardHeader>

                <Divider />

                <CardBody>
                  <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                    <FlexItem>
                      <Button
                        variant="secondary"
                        size="sm"
                        icon={<DatabaseIcon />}
                        onClick={() => {
                          onFilterRecordsByZone(selectedZone.id);
                        }}
                      >
                        View records in zone
                      </Button>
                    </FlexItem>
                    <FlexItem>
                      <Button
                        variant="secondary"
                        size="sm"
                        icon={<DownloadIcon />}
                        onClick={() => {
                          void onExportZoneBind(selectedZone);
                        }}
                      >
                        Export BIND zone file
                      </Button>
                    </FlexItem>
                    {!isReadOnly && (
                      <FlexItem>
                        <Button
                          variant="danger"
                          size="sm"
                          icon={<TrashIcon />}
                          onClick={() => {
                            onOpenDeleteZone(selectedZone);
                          }}
                        >
                          Delete zone
                        </Button>
                      </FlexItem>
                    )}
                  </Flex>
                </CardBody>
              </Card>
            </StackItem>
          </Stack>
        </CardBody>
      </Card>
    );
  }

  if (!selectedRecord) {
    return (
      <Card isFullHeight>
        <CardBody isFilled>
          <EmptyState
            variant="lg"
            titleText="Select a DNS resource record"
            headingLevel="h2"
            icon={DatabaseIcon}
          >
            <EmptyStateBody>
              Choose a DNS record from the directory on the left to inspect or edit its RDATA
              attributes, RFC 1035 wire syntax, and zone authority assignment.
            </EmptyStateBody>
          </EmptyState>
        </CardBody>
      </Card>
    );
  }

  const valSummary = formatRecordValueSummary(selectedRecord.record);
  const typeColor = getRecordTypeColor(selectedRecord.record.type);
  const rdataPairs = getRecordRdataBreakdown(selectedRecord.record);
  const parentZone =
    selectedRecord.zone_id !== null && selectedRecord.zone_id !== undefined
      ? (zones.find((z) => z.id === selectedRecord.zone_id) ?? null)
      : null;

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
                  {selectedRecord.domain}
                </CardTitle>
              </FlexItem>
              <FlexItem>
                <Label color={typeColor} icon={<ShieldAltIcon />}>
                  {selectedRecord.record.type} (TYPE{String(selectedRecord.rr_type_code)})
                </Label>
              </FlexItem>
              <FlexItem>
                <Label color={selectedRecord.zone_name ? 'purple' : 'grey'}>
                  {selectedRecord.zone_name ?? 'Global override'}
                </Label>
              </FlexItem>
              <FlexItem>
                {selectedRecord.enabled ? (
                  <Label color="green" icon={<CheckCircleIcon />}>
                    Active
                  </Label>
                ) : (
                  <Label color="grey" icon={<BanIcon />}>
                    Disabled
                  </Label>
                )}
              </FlexItem>
              {valSummary.badge !== undefined && (
                <FlexItem>
                  <Label color="teal">{valSummary.badge}</Label>
                </FlexItem>
              )}
            </Flex>
          </FlexItem>

          <FlexItem>
            <Content component="p">
              <code>{valSummary.primary}</code> &bull; TTL {String(selectedRecord.ttl)}s
              {selectedRecord.comment ? ` • ${selectedRecord.comment}` : ''}
            </Content>
          </FlexItem>

          <FlexItem>
            <Content component="small">
              Record ID: <code>{selectedRecord.id}</code> &bull; Last updated{' '}
              {formatUpdatedEpoch(selectedRecord.updated_at_epoch)} &bull; Class: IN (Internet)
            </Content>
          </FlexItem>
        </Flex>
      </CardHeader>

      <Divider />

      <CardBody isFilled>
        <Stack hasGutter>
          {/* Section 1: Resource Record & RDATA Configuration */}
          <StackItem>
            <Card isCompact variant="secondary">
              <CardHeader>
                <Flex
                  justifyContent={{ default: 'justifyContentSpaceBetween' }}
                  alignItems={{ default: 'alignItemsCenter' }}
                  gap={{ default: 'gapSm' }}
                >
                  <FlexItem>
                    <strong>Resource Record &amp; RDATA Configuration</strong>
                  </FlexItem>
                  {!isReadOnly && (
                    <FlexItem>
                      <Button
                        variant="secondary"
                        size="sm"
                        icon={<PencilAltIcon />}
                        onClick={() => {
                          onOpenEditRecord(selectedRecord);
                        }}
                      >
                        Edit details
                      </Button>
                    </FlexItem>
                  )}
                </Flex>
              </CardHeader>

              <Divider />

              <CardBody>
                <Stack hasGutter>
                  <StackItem>
                    <Form>
                      <Grid hasGutter>
                        <GridItem span={12} md={6}>
                          <FormGroup
                            label="Canonical owner name (FQDN)"
                            fieldId="record-detail-domain"
                          >
                            <TextInput
                              id="record-detail-domain"
                              value={selectedRecord.domain}
                              isDisabled
                              aria-label="Canonical owner name"
                            />
                          </FormGroup>
                        </GridItem>

                        <GridItem span={12} md={6}>
                          <FormGroup label="Authoritative zone" fieldId="record-detail-zone">
                            <TextInput
                              id="record-detail-zone"
                              value={
                                selectedRecord.zone_name ??
                                'Global Split-Horizon Override (Unzoned)'
                              }
                              isDisabled
                              aria-label="Authoritative zone"
                            />
                          </FormGroup>
                        </GridItem>

                        <GridItem span={12} md={6}>
                          <FormGroup
                            label="Resource record type (IANA)"
                            fieldId="record-detail-type"
                          >
                            <TextInput
                              id="record-detail-type"
                              value={`${selectedRecord.record.type} (TYPE${String(selectedRecord.rr_type_code)})`}
                              isDisabled
                              aria-label="Resource record type"
                            />
                          </FormGroup>
                        </GridItem>

                        <GridItem span={12} md={6}>
                          <FormGroup
                            label="Time To Live (TTL seconds)"
                            fieldId="record-detail-ttl"
                          >
                            <TextInput
                              id="record-detail-ttl"
                              value={`${String(selectedRecord.ttl)} seconds`}
                              isDisabled
                              aria-label="Time to live"
                            />
                          </FormGroup>
                        </GridItem>

                        {rdataPairs.map((pair, idx) => (
                          <GridItem
                            key={pair.label}
                            span={12}
                            md={rdataPairs.length === 1 ? 12 : 6}
                          >
                            <FormGroup
                              label={pair.label}
                              fieldId={`record-detail-rdata-${String(idx)}`}
                            >
                              <TextInput
                                id={`record-detail-rdata-${String(idx)}`}
                                value={pair.value}
                                isDisabled
                                aria-label={pair.label}
                              />
                            </FormGroup>
                          </GridItem>
                        ))}

                        <GridItem span={12}>
                          <FormGroup label="Operator comment" fieldId="record-detail-comment">
                            <TextInput
                              id="record-detail-comment"
                              value={selectedRecord.comment || 'Not provided'}
                              isDisabled
                              aria-label="Operator comment"
                            />
                          </FormGroup>
                        </GridItem>

                        <GridItem span={12}>
                          <FormGroup
                            label="RFC 1035 BIND Master File Wire Line"
                            fieldId="record-detail-bind-line"
                          >
                            <ClipboardCopy
                              isReadOnly
                              hoverTip="Copy RFC 1035 zone line"
                              clickTip="Copied"
                            >
                              {selectedRecord.bind_preview}
                            </ClipboardCopy>
                          </FormGroup>
                        </GridItem>
                      </Grid>
                    </Form>
                  </StackItem>
                </Stack>
              </CardBody>
            </Card>
          </StackItem>

          {/* Section 2: Resolution & Lifecycle Controls */}
          <StackItem>
            <Card isCompact variant="secondary">
              <CardHeader>
                <Flex
                  justifyContent={{ default: 'justifyContentSpaceBetween' }}
                  alignItems={{ default: 'alignItemsCenter' }}
                  gap={{ default: 'gapSm' }}
                >
                  <FlexItem>
                    <strong>Resolution &amp; Lifecycle Controls</strong>
                  </FlexItem>
                  <FlexItem>
                    <Badge isRead={!selectedRecord.enabled}>
                      {selectedRecord.enabled ? 'Active in Resolver' : 'Bypassed'}
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
                        <DescriptionListTerm>Resolution status</DescriptionListTerm>
                        <DescriptionListDescription>
                          {selectedRecord.enabled
                            ? 'Active & Serving Local Answers'
                            : 'Disabled (Queries Fall Through)'}
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                      <DescriptionListGroup>
                        <DescriptionListTerm>Effective TTL</DescriptionListTerm>
                        <DescriptionListDescription>
                          {String(selectedRecord.ttl)} seconds
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                      <DescriptionListGroup>
                        <DescriptionListTerm>Last modified</DescriptionListTerm>
                        <DescriptionListDescription>
                          {formatUpdatedEpoch(selectedRecord.updated_at_epoch)}
                        </DescriptionListDescription>
                      </DescriptionListGroup>
                    </DescriptionList>
                  </StackItem>

                  {!isReadOnly && (
                    <StackItem>
                      <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                        <FlexItem>
                          <Button
                            variant="secondary"
                            size="sm"
                            icon={<CopyIcon />}
                            onClick={() => {
                              onOpenCloneRecord(selectedRecord);
                            }}
                          >
                            Clone record
                          </Button>
                        </FlexItem>

                        <FlexItem>
                          <Button
                            variant="secondary"
                            size="sm"
                            icon={selectedRecord.enabled ? <BanIcon /> : <UndoIcon />}
                            onClick={() => {
                              void onQuickToggleEnabled(selectedRecord);
                            }}
                          >
                            {selectedRecord.enabled ? 'Disable record' : 'Enable record'}
                          </Button>
                        </FlexItem>

                        <FlexItem>
                          <Button
                            variant="danger"
                            size="sm"
                            icon={<TrashIcon />}
                            onClick={() => {
                              onOpenDeleteRecord(selectedRecord);
                            }}
                          >
                            Delete record
                          </Button>
                        </FlexItem>
                      </Flex>
                    </StackItem>
                  )}
                </Stack>
              </CardBody>
            </Card>
          </StackItem>

          {/* Section 3: Inherited Zone Authority */}
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
                      Inherited Zone Authority (
                      {parentZone?.name ?? 'Global Split-Horizon Override'})
                    </strong>
                  </FlexItem>
                  <FlexItem>
                    <Badge isRead={parentZone === null}>
                      {parentZone !== null
                        ? `SOA Serial ${String(parentZone.serial)}`
                        : 'Unzoned'}
                    </Badge>
                  </FlexItem>
                </Flex>
              </CardHeader>

              <Divider />

              <CardBody>
                <Stack hasGutter>
                  <StackItem>
                    <Content component="small">
                      {parentZone !== null
                        ? parentZone.mode === 'authoritative'
                          ? `Authoritative zone '${parentZone.name}' sets AA=1 and synthesizes RFC 2308 negative SOA responses (NXDOMAIN / NODATA) for unconfigured names.`
                          : `Split-horizon zone '${parentZone.name}' overrides matching local records and forwards unmatched queries to the upstream DoH/DoT pool.`
                        : 'Global override record is evaluated before upstream forwarding without enforcing zone-wide NXDOMAIN.'}
                    </Content>
                  </StackItem>
                  <StackItem>
                    <Flex gap={{ default: 'gapXs' }} alignItems={{ default: 'alignItemsCenter' }}>
                      {parentZone !== null ? (
                        <>
                          <FlexItem>
                            <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                              MNAME: {parentZone.primary_ns}
                            </Label>
                          </FlexItem>
                          <FlexItem>
                            <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                              RNAME: {parentZone.admin_email}
                            </Label>
                          </FlexItem>
                          <FlexItem>
                            <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                              Negative TTL: {String(parentZone.minimum)}s
                            </Label>
                          </FlexItem>
                        </>
                      ) : (
                        <FlexItem>
                          <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                            Split-Horizon Upstream Fallback Enabled
                          </Label>
                        </FlexItem>
                      )}
                    </Flex>
                  </StackItem>
                </Stack>
              </CardBody>
            </Card>
          </StackItem>
        </Stack>
      </CardBody>
    </Card>
  );
}
