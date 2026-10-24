import React from 'react';
import {
  Button,
  Checkbox,
  Content,
  ContentVariants,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Stack,
  StackItem
} from '@patternfly/react-core';
import type { DnsZoneView } from '../types/dnsRecords.types';

export interface ZoneDeleteModalProps {
  readonly deletingZone: DnsZoneView | null;
  readonly deleteZoneCascade: boolean;
  readonly isDeletingZone: boolean;
  readonly onClose: () => void;
  readonly onChangeCascade: (checked: boolean) => void;
  readonly onConfirmDeleteZone: () => Promise<void>;
}

export function ZoneDeleteModal({
  deletingZone,
  deleteZoneCascade,
  isDeletingZone,
  onClose,
  onChangeCascade,
  onConfirmDeleteZone
}: ZoneDeleteModalProps): React.JSX.Element {
  return (
    <Modal
      variant={ModalVariant.small}
      isOpen={deletingZone !== null}
      onClose={onClose}
      aria-label="Confirm delete DNS zone"
    >
      <ModalHeader title="Delete DNS Zone" />
      <ModalBody>
        {deletingZone !== null && (
          <Stack hasGutter>
            <StackItem>
              <Content component={ContentVariants.p}>
                Are you sure you want to delete zone <strong>{deletingZone.name}</strong>?
              </Content>
            </StackItem>
            <StackItem>
              <Checkbox
                id="delete-zone-cascade-records"
                label={`Also delete all ${String(deletingZone.record_count)} record(s) belonging to this zone (otherwise they become unzoned overrides)`}
                isChecked={deleteZoneCascade}
                onChange={(_e, checked) => { onChangeCascade(checked); }}
              />
            </StackItem>
          </Stack>
        )}
      </ModalBody>
      <ModalFooter>
        <Button
          variant="danger"
          isLoading={isDeletingZone}
          isDisabled={isDeletingZone}
          onClick={() => void onConfirmDeleteZone()}
        >
          Confirm Delete Zone
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={isDeletingZone}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
