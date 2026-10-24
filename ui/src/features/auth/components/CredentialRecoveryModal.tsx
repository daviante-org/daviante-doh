import React from 'react';
import {
  Button,
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
import type { CredentialRecoveryModalProps } from '../types/auth.types';

export function CredentialRecoveryModal({
  isOpen,
  onClose
}: CredentialRecoveryModalProps): React.JSX.Element {
  return (
    <Modal
      variant={ModalVariant.medium}
      isOpen={isOpen}
      onClose={onClose}
      aria-label="Administrator Credential Recovery"
    >
      <ModalHeader title="Administrator Credential Recovery & Reset" />
      <ModalBody>
        <Stack hasGutter>
          <StackItem>
            <Content component={ContentVariants.p}>
              For security reasons, Daviante DoH does not expose unauthenticated self-service
              password reset endpoints.
            </Content>
          </StackItem>
          <StackItem>
            <Content component={ContentVariants.p}>
              <strong>1. Local Argon2id Principal Rotation:</strong> Generate a new Argon2id hash
              (minimum parameters <code>m=19456, t=2, p=1</code>) and update{' '}
              <code>DOH_ADMIN_PASSWORD_HASH</code> in your container or host secret manager, then
              restart the control-plane service.
            </Content>
          </StackItem>
          <StackItem>
            <Content component={ContentVariants.p}>
              <strong>2. Enterprise OIDC / SSO Recovery:</strong> If your organization uses OpenID
              Connect Single Sign-On, reset your credentials or MFA token through your identity
              provider portal (Keycloak, Okta, or Microsoft Entra ID).
            </Content>
          </StackItem>
        </Stack>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" onClick={onClose}>
          Close
        </Button>
      </ModalFooter>
    </Modal>
  );
}
