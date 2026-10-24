import React from 'react';
import {
  Alert,
  Button,
  Card,
  CardBody,
  Content,
  ContentVariants,
  Flex,
  FlexItem,
  Grid,
  GridItem,
  PageSection,
  Stack,
  StackItem
} from '@patternfly/react-core';
import { useDnsRecordsWorkspace } from '../hooks/useDnsRecordsWorkspace';
import type { LocalDnsRecordsFeatureProps } from '../types/dnsRecords.types';
import { BulkImportModal } from './BulkImportModal';
import { CloudflareRecordModal } from './CloudflareRecordModal';
import { RecordDeleteModal } from './RecordDeleteModal';
import { RecordsTable } from './RecordsTable';
import { RecordsToolbar } from './RecordsToolbar';
import { ZoneContextHeaderCard } from './ZoneContextHeaderCard';
import { ZoneDeleteModal } from './ZoneDeleteModal';
import { ZoneExportModal } from './ZoneExportModal';
import { ZoneFormModal } from './ZoneFormModal';
import { ZonesNavigatorCard } from './ZonesNavigatorCard';

export function LocalDnsRecordsFeature({
  role
}: LocalDnsRecordsFeatureProps): React.JSX.Element {
  const ws = useDnsRecordsWorkspace(role);

  return (
    <PageSection isFilled>
      <Stack hasGutter>
        <StackItem>
          <Flex
            justifyContent={{ default: 'justifyContentSpaceBetween' }}
            alignItems={{ default: 'alignItemsCenter' }}
            gap={{ default: 'gapMd' }}
          >
            <FlexItem>
              <Content component={ContentVariants.h1}>Local DNS Zones &amp; Records</Content>
              <Content component={ContentVariants.p}>
                Manage authoritative &amp; split-horizon DNS zones, SOA parameters, and all 29 IANA
                resource record types with RFC 2181 CNAME exclusivity and wire-format validation.
              </Content>
            </FlexItem>
            {!ws.isReadOnly && (
              <FlexItem>
                <Flex gap={{ default: 'gapSm' }}>
                  <FlexItem>
                    <Button variant="primary" onClick={ws.openCreateRecordModal}>
                      Add Record
                    </Button>
                  </FlexItem>
                  <FlexItem>
                    <Button
                      variant="secondary"
                      onClick={() => {
                        ws.setImportError(null);
                        ws.setImportResult(null);
                        ws.setIsImportModalOpen(true);
                      }}
                    >
                      Bulk Import
                    </Button>
                  </FlexItem>
                  <FlexItem>
                    <Button variant="secondary" onClick={ws.openCreateZoneModal}>
                      Create Zone
                    </Button>
                  </FlexItem>
                </Flex>
              </FlexItem>
            )}
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

        <StackItem>
          <Grid hasGutter>
            <GridItem md={3} sm={12}>
              <ZonesNavigatorCard
                zones={ws.zones}
                filteredZones={ws.filteredZones}
                selectedZoneKey={ws.selectedZoneKey}
                zoneSearchInput={ws.zoneSearchInput}
                isReadOnly={ws.isReadOnly}
                onSelectZoneKey={(id) => {
                  ws.setSelectedZoneKey(id);
                  ws.setPage(1);
                }}
                onZoneSearchChange={ws.setZoneSearchInput}
                onOpenCreateZone={ws.openCreateZoneModal}
              />
            </GridItem>

            <GridItem md={9} sm={12}>
              <Stack hasGutter>
                {ws.activeZone !== null && (
                  <StackItem>
                    <ZoneContextHeaderCard
                      activeZone={ws.activeZone}
                      isReadOnly={ws.isReadOnly}
                      onExportZoneBind={ws.handleExportZoneBind}
                      onEditZone={ws.openEditZoneModal}
                      onDeleteZone={(zone) => {
                        ws.setDeletingZone(zone);
                        ws.setDeleteZoneCascade(false);
                      }}
                    />
                  </StackItem>
                )}

                <StackItem>
                  <Card>
                    <CardBody>
                      <RecordsToolbar
                        searchInput={ws.searchInput}
                        filterRecordType={ws.filterRecordType}
                        categoryFilter={ws.categoryFilter}
                        filterEnabled={ws.filterEnabled}
                        selectedCount={ws.selectedRecordIds.size}
                        total={ws.total}
                        page={ws.page}
                        perPage={ws.perPage}
                        isReadOnly={ws.isReadOnly}
                        onSearchChange={ws.setSearchInput}
                        onRecordTypeChange={ws.handleSelectRecordTypeFilter}
                        onCategoryChange={ws.handleSelectCategoryFilter}
                        onEnabledFilterChange={ws.setFilterEnabled}
                        onBulkDelete={ws.handleBulkDeleteSelected}
                        onPageChange={ws.setPage}
                        onPerPageChange={ws.setPerPage}
                      />

                      <RecordsTable
                        isLoading={ws.isLoading}
                        visibleRecords={ws.visibleRecords}
                        activeZone={ws.activeZone}
                        isReadOnly={ws.isReadOnly}
                        expandedRecordIds={ws.expandedRecordIds}
                        selectedRecordIds={ws.selectedRecordIds}
                        onToggleExpand={ws.toggleExpandRecord}
                        onToggleSelect={ws.toggleSelectRecord}
                        onToggleSelectAllPage={ws.toggleSelectAllPage}
                        onQuickToggleEnabled={ws.handleQuickToggleRecordEnabled}
                        onOpenCreateRecord={ws.openCreateRecordModal}
                        onOpenEditRecord={ws.openEditRecordModal}
                        onOpenCloneRecord={ws.openCloneRecordModal}
                        onOpenDeleteRecord={ws.setDeletingRecord}
                      />
                    </CardBody>
                  </Card>
                </StackItem>
              </Stack>
            </GridItem>
          </Grid>
        </StackItem>
      </Stack>

      <CloudflareRecordModal
        isOpen={ws.isRecordModalOpen}
        editRecord={ws.editingRecord}
        isCloneMode={ws.isCloningRecord}
        activeZone={ws.activeZone}
        existingRecords={ws.records}
        onClose={() => { ws.setIsRecordModalOpen(false); }}
        onSubmitRecord={ws.handleSubmitRecord}
      />

      <ZoneFormModal
        isOpen={ws.isZoneModalOpen}
        editingZone={ws.editingZone}
        zoneForm={ws.zoneForm}
        zoneFormError={ws.zoneFormError}
        isSavingZone={ws.isSavingZone}
        onClose={() => { ws.setIsZoneModalOpen(false); }}
        onUpdateZoneForm={ws.setZoneForm}
        onSaveZone={ws.handleSaveZone}
      />

      <ZoneDeleteModal
        deletingZone={ws.deletingZone}
        deleteZoneCascade={ws.deleteZoneCascade}
        isDeletingZone={ws.isDeletingZone}
        onClose={() => { ws.setDeletingZone(null); }}
        onChangeCascade={ws.setDeleteZoneCascade}
        onConfirmDeleteZone={ws.handleConfirmDeleteZone}
      />

      <ZoneExportModal
        exportBindOutput={ws.exportBindOutput}
        onClose={() => { ws.setExportBindOutput(null); }}
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
        onClose={() => { ws.setIsImportModalOpen(false); }}
        onChangeFormat={ws.setImportFormat}
        onChangeText={ws.setImportText}
        onChangeDefaultTtl={ws.setImportDefaultTtl}
        onSubmitImport={ws.handleBulkImportSubmit}
      />

      <RecordDeleteModal
        deletingRecord={ws.deletingRecord}
        isDeleting={ws.isDeleting}
        onClose={() => { ws.setDeletingRecord(null); }}
        onConfirmDelete={ws.handleConfirmDeleteRecord}
      />
    </PageSection>
  );
}
