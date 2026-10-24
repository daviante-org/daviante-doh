import React from 'react';
import {
  Button,
  CodeBlock,
  CodeBlockCode,
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
import type { LocalDnsRecordView } from '../types/dnsRecords.types';

export interface RecordDeleteModalProps {
  readonly deletingRecord: LocalDnsRecordView | null;
  readonly isDeleting: boolean;
  readonly onClose: () => void;
  readonly onConfirmDelete: () => Promise<void>;
}

export function RecordDeleteModal({
  deletingRecord,
  isDeleting,
  onClose,
  onConfirmDelete
}: RecordDeleteModalProps): React.JSX.Element {
  return (
    <Modal
      variant={ModalVariant.small}
      isOpen={deletingRecord !== null}
      onClose={onClose}
      aria-label="Confirm delete DNS record"
    >
      <ModalHeader title="Delete Local DNS Record" />
      <ModalBody>
        {deletingRecord !== null && (
          <Stack hasGutter>
            <StackItem>
              <Content component={ContentVariants.p}>
                Are you sure you want to permanently delete this{' '}
                <strong>{deletingRecord.record.type}</strong> record for{' '}
                <strong>{deletingRecord.domain}</strong>?
              </Content>
            </StackItem>
            <StackItem>
              <CodeBlock>
                <CodeBlockCode>{deletingRecord.bind_preview}</CodeBlockCode>
              </CodeBlock>
            </StackItem>
          </Stack>
        )}
      </ModalBody>
      <ModalFooter>
        <Button
          variant="danger"
          isLoading={isDeleting}
          isDisabled={isDeleting}
          onClick={() => void onConfirmDelete()}
        >
          Confirm Delete
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={isDeleting}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
