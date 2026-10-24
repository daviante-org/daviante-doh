import React from 'react';
import {
  Alert,
  Button,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Stack,
  StackItem,
  Switch,
  TextInput
} from '@patternfly/react-core';
import type { ZoneFormState } from '../hooks/useDnsRecordsWorkspace';
import type { DnsZoneView, ZoneMode } from '../types/dnsRecords.types';

export interface ZoneFormModalProps {
  readonly isOpen: boolean;
  readonly editingZone: DnsZoneView | null;
  readonly zoneForm: ZoneFormState;
  readonly zoneFormError: string | null;
  readonly isSavingZone: boolean;
  readonly onClose: () => void;
  readonly onUpdateZoneForm: (updater: (prev: ZoneFormState) => ZoneFormState) => void;
  readonly onSaveZone: () => Promise<void>;
}

export function ZoneFormModal({
  isOpen,
  editingZone,
  zoneForm,
  zoneFormError,
  isSavingZone,
  onClose,
  onUpdateZoneForm,
  onSaveZone
}: ZoneFormModalProps): React.JSX.Element {
  return (
    <Modal
      variant={ModalVariant.large}
      isOpen={isOpen}
      onClose={onClose}
      aria-label={editingZone ? 'Edit DNS Zone' : 'Create DNS Zone'}
    >
      <ModalHeader
        title={
          editingZone !== null
            ? `Edit DNS Zone (${editingZone.name})`
            : 'Create Authoritative / Split-Horizon DNS Zone'
        }
        description="Configure the zone apex domain, resolution mode, and RFC 1035 Start of Authority (SOA) timers."
      />
      <ModalBody>
        <Stack hasGutter>
          {zoneFormError !== null && (
            <StackItem>
              <Alert variant="danger" isInline title={zoneFormError} />
            </StackItem>
          )}
          <StackItem>
            <Form>
              <Grid hasGutter>
                <GridItem md={6}>
                  <FormGroup label="Zone Apex Domain" isRequired fieldId="zone-name">
                    <TextInput
                      id="zone-name"
                      value={zoneForm.name}
                      maxLength={253}
                      placeholder="internal.corp"
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, name: val })); }
                      }
                    />
                    <FormHelperText>
                      <HelperText>
                        <HelperTextItem>
                          Records inside this zone can use <code>@</code> for apex or relative
                          subdomains like <code>api</code>.
                        </HelperTextItem>
                      </HelperText>
                    </FormHelperText>
                  </FormGroup>
                </GridItem>
                <GridItem md={6}>
                  <FormGroup label="Zone Resolution Mode" isRequired fieldId="zone-mode">
                    <FormSelect
                      id="zone-mode"
                      value={zoneForm.mode}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, mode: val as ZoneMode })); }
                      }
                    >
                      <FormSelectOption
                        value="authoritative"
                        label="Authoritative Zone (Return NXDOMAIN/NODATA + SOA for missing records)"
                      />
                      <FormSelectOption
                        value="override"
                        label="Split-Horizon Override (Forward unmatched queries to upstream)"
                      />
                    </FormSelect>
                  </FormGroup>
                </GridItem>

                <GridItem md={6}>
                  <FormGroup
                    label="Primary Nameserver (SOA MNAME)"
                    isRequired
                    fieldId="zone-primary-ns"
                  >
                    <TextInput
                      id="zone-primary-ns"
                      value={zoneForm.primaryNs}
                      maxLength={253}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, primaryNs: val })); }
                      }
                    />
                  </FormGroup>
                </GridItem>
                <GridItem md={6}>
                  <FormGroup
                    label="Responsible Mailbox (SOA RNAME)"
                    isRequired
                    fieldId="zone-admin-email"
                  >
                    <TextInput
                      id="zone-admin-email"
                      value={zoneForm.adminEmail}
                      maxLength={253}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, adminEmail: val })); }
                      }
                    />
                  </FormGroup>
                </GridItem>

                <GridItem md={3}>
                  <FormGroup label="Refresh (s)" isRequired fieldId="zone-refresh">
                    <TextInput
                      id="zone-refresh"
                      type="number"
                      value={zoneForm.refresh}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, refresh: val })); }
                      }
                    />
                  </FormGroup>
                </GridItem>
                <GridItem md={3}>
                  <FormGroup label="Retry (s)" isRequired fieldId="zone-retry">
                    <TextInput
                      id="zone-retry"
                      type="number"
                      value={zoneForm.retry}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, retry: val })); }
                      }
                    />
                  </FormGroup>
                </GridItem>
                <GridItem md={3}>
                  <FormGroup label="Expire (s)" isRequired fieldId="zone-expire">
                    <TextInput
                      id="zone-expire"
                      type="number"
                      value={zoneForm.expire}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, expire: val })); }
                      }
                    />
                  </FormGroup>
                </GridItem>
                <GridItem md={3}>
                  <FormGroup label="Negative Cache TTL (s)" isRequired fieldId="zone-minimum">
                    <TextInput
                      id="zone-minimum"
                      type="number"
                      value={zoneForm.minimum}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, minimum: val })); }
                      }
                    />
                  </FormGroup>
                </GridItem>

                <GridItem md={4}>
                  <FormGroup label="Default Record TTL (s)" isRequired fieldId="zone-default-ttl">
                    <TextInput
                      id="zone-default-ttl"
                      type="number"
                      value={zoneForm.defaultTtl}
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, defaultTtl: val })); }
                      }
                    />
                  </FormGroup>
                </GridItem>
                <GridItem md={4}>
                  <FormGroup label="Zone Status" fieldId="zone-enabled">
                    <Switch
                      id="zone-enabled"
                      label="Zone enabled"
                      isChecked={zoneForm.enabled}
                      onChange={(_e, checked) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, enabled: checked })); }
                      }
                    />
                  </FormGroup>
                </GridItem>
                <GridItem md={4}>
                  <FormGroup label="Comment" fieldId="zone-comment">
                    <TextInput
                      id="zone-comment"
                      value={zoneForm.comment}
                      maxLength={256}
                      placeholder="Optional note"
                      onChange={(_e, val) =>
                        { onUpdateZoneForm((prev) => ({ ...prev, comment: val })); }
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
          isLoading={isSavingZone}
          isDisabled={isSavingZone}
          onClick={() => void onSaveZone()}
        >
          {editingZone !== null ? 'Save Zone Changes' : 'Create Zone'}
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={isSavingZone}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
