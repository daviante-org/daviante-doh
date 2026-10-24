import React, { useEffect, useState } from 'react';
import {
  Button,
  Flex,
  FlexItem,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Tab,
  Tabs,
  TabTitleText
} from '@patternfly/react-core';
import { APACHE_LICENSE_URL, DAVIANTE_ORG_URL } from '../../constants';
import { isSafeHrefUrl } from '../../utils';
import type { LegalPoliciesModalProps, LegalPolicyTab } from './LegalPoliciesModal.types';
import { PrivacyTabContent } from './PrivacyTabContent';
import { RfcMatrixTabContent } from './RfcMatrixTabContent';
import { SecurityTabContent } from './SecurityTabContent';
import { TermsTabContent } from './TermsTabContent';

export function LegalPoliciesModal({
  isOpen,
  initialTab = 'terms',
  onClose
}: LegalPoliciesModalProps): React.JSX.Element {
  const [activeTab, setActiveTab] = useState<LegalPolicyTab>(initialTab);

  useEffect(() => {
    if (isOpen) {
      setActiveTab(initialTab);
    }
  }, [isOpen, initialTab]);

  return (
    <Modal
      variant={ModalVariant.large}
      isOpen={isOpen}
      onClose={onClose}
      aria-label="Daviante DoH Governance, Terms, Privacy & Security Policies"
    >
      <ModalHeader
        title="Daviante DoH — Governance, Terms, Privacy & Security Policies"
        description="Official operational governance, zero-telemetry data privacy commitment, and RFC/OWASP security architecture maintained by Daviante Organization."
      />
      <ModalBody>
        <Tabs
          activeKey={activeTab}
          onSelect={(_e, key) => {
            setActiveTab(key as LegalPolicyTab);
          }}
          aria-label="Governance and Legal Policy Sections"
        >
          <Tab eventKey="terms" title={<TabTitleText>Terms of Service & License</TabTitleText>}>
            <TermsTabContent />
          </Tab>
          <Tab eventKey="privacy" title={<TabTitleText>Data Privacy & Telemetry</TabTitleText>}>
            <PrivacyTabContent />
          </Tab>
          <Tab
            eventKey="security"
            title={<TabTitleText>Security Architecture & Disclosure</TabTitleText>}
          >
            <SecurityTabContent />
          </Tab>
          <Tab eventKey="rfcs" title={<TabTitleText>RFC & Standards Compliance</TabTitleText>}>
            <RfcMatrixTabContent />
          </Tab>
        </Tabs>
      </ModalBody>
      <ModalFooter>
        <Flex
          justifyContent={{ default: 'justifyContentSpaceBetween' }}
          alignItems={{ default: 'alignItemsCenter' }}
          className="pf-v6-u-w-100"
          gap={{ default: 'gapSm' }}
        >
          <FlexItem>
            <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
              <FlexItem>
                <Label isCompact color="blue">
                  Apache-2.0 License
                </Label>
              </FlexItem>
              {isSafeHrefUrl(DAVIANTE_ORG_URL) && (
                <FlexItem>
                  <Button
                    variant="link"
                    isInline
                    component="a"
                    href={DAVIANTE_ORG_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    github.com/orgs/daviante-org
                  </Button>
                </FlexItem>
              )}
              {isSafeHrefUrl(APACHE_LICENSE_URL) && (
                <FlexItem>
                  <Button
                    variant="link"
                    isInline
                    component="a"
                    href={APACHE_LICENSE_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Apache 2.0 Full Text
                  </Button>
                </FlexItem>
              )}
            </Flex>
          </FlexItem>
          <FlexItem>
            <Button variant="primary" onClick={onClose}>
              Close
            </Button>
          </FlexItem>
        </Flex>
      </ModalFooter>
    </Modal>
  );
}
