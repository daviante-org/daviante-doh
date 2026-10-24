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
  Title
} from '@patternfly/react-core';
import { PlusCircleIcon, SyncAltIcon, UploadIcon } from '@patternfly/react-icons';
import { useDnsRecordsWorkspace } from '../hooks/useDnsRecordsWorkspace';
import type { LocalDnsRecordsFeatureProps } from '../types/dnsRecords.types';
import { BulkImportModal } from './BulkImportModal';
import { CloudflareRecordModal } from './CloudflareRecordModal';
import { RecordDeleteModal } from './RecordDeleteModal';
import { RecordDetailCard } from './RecordDetailCard';
import { RecordDirectoryCard } from './RecordDirectoryCard';
import { ZoneDeleteModal } from './ZoneDeleteModal';
import { ZoneExportModal } from './ZoneExportModal';
import { ZoneFormModal } from './ZoneFormModal';

export function LocalDnsRecordsFeature({
  role
}: LocalDnsRecordsFeatureProps): React.JSX.Element {
  const ws = useDnsRecordsWorkspace(role);

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
                  Local DNS Zones &amp; Records
                </Title>
                <Content component="p">
                  Manage authoritative &amp; split-horizon DNS zones, SOA parameters, and all 29
                  IANA resource record types with RFC 2181 CNAME exclusivity and wire-format
                  validation.
                </Content>
              </FlexItem>
              <FlexItem>
                <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                  {!ws.isReadOnly && (
                    <>
                      <FlexItem>
                        <Button
                          variant="secondary"
                          icon={<UploadIcon />}
                          onClick={() => {
                            ws.setImportError(null);
                            ws.setImportResult(null);
                            ws.setIsImportModalOpen(true);
                          }}
                        >
                          Bulk import
                        </Button>
                      </FlexItem>
                      <FlexItem>
                        <Button
                          variant="secondary"
                          icon={<PlusCircleIcon />}
                          onClick={ws.openCreateZoneModal}
                        >
                          Create zone
                        </Button>
                      </FlexItem>
                    </>
                  )}
                  <FlexItem>
                    <Button
                      variant="secondary"
                      icon={<SyncAltIcon />}
                      isLoading={ws.isLoading}
                      onClick={() => {
                        void ws.loadZonesAndRecords();
                      }}
                    >
                      Refresh
                    </Button>
                  </FlexItem>
                </Flex>
              </FlexItem>
            </Flex>
          </StackItem>

          {ws.pageError !== null && (
            <StackItem>
              <Alert variant="danger" isInline title={ws.pageError} />
            </StackItem>
          )}

          {ws.actionSuccess !== null && (
            <StackItem>
              <Alert variant="success" isInline title={ws.actionSuccess} />
            </StackItem>
          )}
        </Stack>
      </PageSection>

      <PageSection isFilled>
        <Grid hasGutter>
          <GridItem span={12} lg={4}>
            <RecordDirectoryCard
              directoryMode={ws.directoryMode}
              isLoading={ws.isLoading}
              isReadOnly={ws.isReadOnly}
              zones={ws.zones}
              filteredZones={ws.filteredZones}
              selectedZoneKey={ws.selectedZoneKey}
              selectedZone={ws.selectedZone}
              zoneSearchInput={ws.zoneSearchInput}
              visibleRecords={ws.visibleRecords}
              selectedRecord={ws.selectedRecord}
              total={ws.total}
              page={ws.page}
              perPage={ws.perPage}
              searchInput={ws.searchInput}
              filterRecordType={ws.filterRecordType}
              filterEnabled={ws.filterEnabled}
              onChangeDirectoryMode={ws.setDirectoryMode}
              onSelectRecord={ws.setSelectedRecordId}
              onSelectZoneKey={ws.setSelectedZoneKey}
              onSearchChange={ws.setSearchInput}
              onZoneSearchChange={ws.setZoneSearchInput}
              onRecordTypeChange={ws.handleSelectRecordTypeFilter}
              onEnabledFilterChange={ws.setFilterEnabled}
              onClearFilters={ws.handleClearRecordFilters}
              onPageChange={ws.setPage}
              onPerPageChange={ws.setPerPage}
              onOpenCreateRecordModal={ws.openCreateRecordModal}
              onOpenCreateZoneModal={ws.openCreateZoneModal}
            />
          </GridItem>

          <GridItem span={12} lg={8}>
            <RecordDetailCard
              directoryMode={ws.directoryMode}
              isReadOnly={ws.isReadOnly}
              selectedRecord={ws.selectedRecord}
              selectedZone={ws.selectedZone}
              zones={ws.zones}
              onOpenEditRecord={ws.openEditRecordModal}
              onOpenCloneRecord={ws.openCloneRecordModal}
              onQuickToggleEnabled={ws.handleQuickToggleRecordEnabled}
              onOpenDeleteRecord={ws.setDeletingRecord}
              onOpenEditZone={ws.openEditZoneModal}
              onExportZoneBind={ws.handleExportZoneBind}
              onOpenDeleteZone={(zone) => {
                ws.setDeletingZone(zone);
                ws.setDeleteZoneCascade(false);
              }}
              onFilterRecordsByZone={(zoneId) => {
                ws.setSelectedZoneKey(zoneId);
                ws.setDirectoryMode('records');
                ws.setPage(1);
              }}
            />
          </GridItem>
        </Grid>
      </PageSection>

      <CloudflareRecordModal
        isOpen={ws.isRecordModalOpen}
        editRecord={ws.editingRecord}
        isCloneMode={ws.isCloningRecord}
        activeZone={ws.activeZone}
        existingRecords={ws.records}
        onClose={() => {
          ws.setIsRecordModalOpen(false);
        }}
        onSubmitRecord={ws.handleSubmitRecord}
      />

      <ZoneFormModal
        isOpen={ws.isZoneModalOpen}
        editingZone={ws.editingZone}
        zoneForm={ws.zoneForm}
        zoneFormError={ws.zoneFormError}
        isSavingZone={ws.isSavingZone}
        onClose={() => {
          ws.setIsZoneModalOpen(false);
        }}
        onUpdateZoneForm={ws.setZoneForm}
        onSaveZone={ws.handleSaveZone}
      />

      <ZoneDeleteModal
        deletingZone={ws.deletingZone}
        deleteZoneCascade={ws.deleteZoneCascade}
        isDeletingZone={ws.isDeletingZone}
        onClose={() => {
          ws.setDeletingZone(null);
        }}
        onChangeCascade={ws.setDeleteZoneCascade}
        onConfirmDeleteZone={ws.handleConfirmDeleteZone}
      />

      <ZoneExportModal
        exportBindOutput={ws.exportBindOutput}
        onClose={() => {
          ws.setExportBindOutput(null);
        }}
      />

      <BulkImportModal
        isOpen={ws.isImportModalOpen}
        activeZone={ws.activeZone}
        importFormat={ws.importFormat}
        importText={ws.importText}
        importDefaultTtl={ws.importDefaultTtl}
        isImporting={ws.isImporting}
        importError={ws.importError}
        importResult={ws.importResult}
        onClose={() => {
          ws.setIsImportModalOpen(false);
        }}
        onChangeFormat={ws.setImportFormat}
        onChangeText={ws.setImportText}
        onChangeDefaultTtl={ws.setImportDefaultTtl}
        onSubmitImport={ws.handleBulkImportSubmit}
      />

      <RecordDeleteModal
        deletingRecord={ws.deletingRecord}
        isDeleting={ws.isDeleting}
        onClose={() => {
          ws.setDeletingRecord(null);
        }}
        onConfirmDelete={ws.handleConfirmDeleteRecord}
      />
    </>
  );
}
