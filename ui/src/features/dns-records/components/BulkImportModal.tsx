import React from 'react';
import {
  Alert,
  Button,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Stack,
  StackItem,
  TextArea,
  TextInput
} from '@patternfly/react-core';
import type { BulkImportRecordsResponse, DnsZoneView } from '../types/dnsRecords.types';

export interface BulkImportModalProps {
  readonly isOpen: boolean;
  readonly activeZone: DnsZoneView | null;
  readonly importFormat: 'bind' | 'json';
  readonly importText: string;
  readonly importDefaultTtl: string;
  readonly isImporting: boolean;
  readonly importError: string | null;
  readonly importResult: BulkImportRecordsResponse | null;
  readonly onClose: () => void;
  readonly onChangeFormat: (fmt: 'bind' | 'json') => void;
  readonly onChangeText: (text: string) => void;
  readonly onChangeDefaultTtl: (ttl: string) => void;
  readonly onSubmitImport: () => Promise<void>;
}

export function BulkImportModal({
  isOpen,
  activeZone,
  importFormat,
  importText,
  importDefaultTtl,
  isImporting,
  importError,
  importResult,
  onClose,
  onChangeFormat,
  onChangeText,
  onChangeDefaultTtl,
  onSubmitImport
}: BulkImportModalProps): React.JSX.Element {
  return (
    <Modal
      variant={ModalVariant.large}
      isOpen={isOpen}
      onClose={onClose}
      aria-label="Bulk Import DNS Records"
    >
      <ModalHeader
        title={`Bulk Import DNS Records ${activeZone ? `(into Zone: ${activeZone.name})` : '(Global / Auto-Zoned)'}`}
        description="Import RFC 1035 BIND zone file lines ($ORIGIN, $TTL, @, relative owners) or a structured JSON array."
      />
      <ModalBody>
        <Stack hasGutter>
          {importError !== null && (
            <StackItem>
              <Alert variant="danger" isInline title={importError} />
            </StackItem>
          )}
          {importResult !== null && (
            <StackItem>
              <Alert
                variant={importResult.errors.length === 0 ? 'success' : 'warning'}
                isInline
                title={`Imported ${String(importResult.imported_count)} record(s), skipped ${String(importResult.skipped_count)} line(s).`}
              >
                {importResult.errors.length > 0 && (
                  <ul>
                    {importResult.errors.map((errMsg, idx) => (
                      <li key={idx}>{errMsg}</li>
                    ))}
                  </ul>
                )}
              </Alert>
            </StackItem>
          )}
          <StackItem>
            <Form>
              <Grid hasGutter>
                <GridItem md={6}>
                  <FormGroup label="Import Format" isRequired fieldId="import-format">
                    <FormSelect
                      id="import-format"
                      value={importFormat}
                      onChange={(_e, val) => { onChangeFormat(val as 'bind' | 'json'); }}
                    >
                      <FormSelectOption
                        value="bind"
                        label="RFC 1035 BIND Master Zone File Format"
                      />
                      <FormSelectOption value="json" label="Structured JSON Records Array" />
                    </FormSelect>
                  </FormGroup>
                </GridItem>
                {importFormat === 'bind' && (
                  <GridItem md={6}>
                    <FormGroup label="Default Fallback TTL (s)" fieldId="import-default-ttl">
                      <TextInput
                        id="import-default-ttl"
                        type="number"
                        value={importDefaultTtl}
                        onChange={(_e, val) => { onChangeDefaultTtl(val); }}
                      />
                    </FormGroup>
                  </GridItem>
                )}
                <GridItem md={12}>
                  <FormGroup
                    label={importFormat === 'bind' ? 'BIND Zone Lines' : 'JSON Payload'}
                    isRequired
                    fieldId="import-payload"
                  >
                    <TextArea
                      id="import-payload"
                      rows={10}
                      value={importText}
                      onChange={(_e, val) => { onChangeText(val); }}
                      spellCheck={false}
                      placeholder={
                        importFormat === 'bind'
                          ? '$ORIGIN internal.corp.\n$TTL 300\n@ IN A 10.20.0.1\napi IN A 10.20.0.10\nmail IN MX 10 mx1.internal.corp.'
                          : '[{"domain":"api.internal.corp","ttl":300,"enabled":true,"comment":"","record":{"type":"A","ip":"10.20.0.10","auto_ptr":true}}]'
                      }
                    />
                  </FormGroup>
                </GridItem>
              </Grid>
            </Form>
          </StackItem>
        </Stack>
      </ModalBody>
      <ModalFooter>
        <Button
          variant="primary"
          isLoading={isImporting}
          isDisabled={isImporting}
          onClick={() => void onSubmitImport()}
        >
          Run Bulk Import
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={isImporting}>
          Close
        </Button>
      </ModalFooter>
    </Modal>
  );
}
