import React from 'react';
import {
  Button,
  CodeBlock,
  CodeBlockCode,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant
} from '@patternfly/react-core';

export interface ZoneExportModalProps {
  readonly exportBindOutput: { readonly zoneName: string; readonly content: string } | null;
  readonly onClose: () => void;
}

export function ZoneExportModal({
  exportBindOutput,
  onClose
}: ZoneExportModalProps): React.JSX.Element {
  return (
    <Modal
      variant={ModalVariant.large}
      isOpen={exportBindOutput !== null}
      onClose={onClose}
      aria-label="Exported BIND Zone File"
    >
      <ModalHeader
        title={`RFC 1035 Master Zone File — ${exportBindOutput?.zoneName ?? ''}`}
        description="Copy or save this standard BIND master file for backup or secondary nameserver synchronization."
      />
      <ModalBody>
        {exportBindOutput !== null && (
          <CodeBlock>
            <CodeBlockCode>{exportBindOutput.content}</CodeBlockCode>
          </CodeBlock>
        )}
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" onClick={onClose}>
          Close
        </Button>
      </ModalFooter>
    </Modal>
  );
}
