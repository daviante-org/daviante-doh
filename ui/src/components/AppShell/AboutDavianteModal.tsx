import React from 'react';
import {
  AboutModal,
  Button,
  Content,
  ContentVariants,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  FlexItem,
  Stack,
  StackItem
} from '@patternfly/react-core';
import { DAVIANTE_ORG_URL } from '../../constants';
import { isSafeHrefUrl } from '../../utils';
import type { AboutDavianteModalProps } from './AppShell.types';

export function AboutDavianteModal({
  isOpen,
  role,
  authMethod,
  onClose,
  onOpenPolicyTab
}: AboutDavianteModalProps): React.JSX.Element {
  return (
    <AboutModal
      isOpen={isOpen}
      onClose={onClose}
      trademark="Copyright © 2026 Daviante Organization (https://github.com/orgs/daviante-org). Licensed under the Apache License, Version 2.0."
      brandImageSrc="/favicon.svg"
      brandImageAlt="Daviante DoH Emblem"
      productName="Daviante DoH Enterprise Control-Plane"
    >
      <Stack hasGutter>
        <StackItem>
          <Content component={ContentVariants.p}>
            High-assurance DNS-over-HTTPS (RFC 8484) authoritative &amp; split-horizon DNS engine,
            protective threat sinkhole, and enterprise control-plane engineered by{' '}
            {isSafeHrefUrl(DAVIANTE_ORG_URL) ? (
              <a href={DAVIANTE_ORG_URL} target="_blank" rel="noopener noreferrer">
                Daviante Organization
              </a>
            ) : (
              'Daviante Organization'
            )}
            .
          </Content>
        </StackItem>
        <StackItem>
          <DescriptionList isCompact columnModifier={{ default: '2Col' }}>
            <DescriptionListGroup>
              <DescriptionListTerm>Release Version</DescriptionListTerm>
              <DescriptionListDescription>
                <code>v0.2.0-enterprise</code>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Core Engine Stack</DescriptionListTerm>
              <DescriptionListDescription>
                Rust 2021 · Tokio · Axum · Hickory-DNS · Redb ACID Store
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Control-Plane UI Stack</DescriptionListTerm>
              <DescriptionListDescription>
                React 19 · TypeScript 5.8 (Strict) · PatternFly 6 · Zod Runtime Validation
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Supported DNS RR Types</DescriptionListTerm>
              <DescriptionListDescription>
                All 29 IANA Resource Record Types + RFC 1035 Master Zones
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Security Posture</DescriptionListTerm>
              <DescriptionListDescription>
                OWASP ASVS v4.0 Level 2 · Argon2id · Strict CSP · Zero External Telemetry
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Active Principal Session</DescriptionListTerm>
              <DescriptionListDescription>
                {role} ({authMethod.toUpperCase()})
              </DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        </StackItem>
        <StackItem>
          <Flex gap={{ default: 'gapSm' }}>
            <FlexItem>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  onClose();
                  onOpenPolicyTab('terms');
                }}
              >
                Terms &amp; License
              </Button>
            </FlexItem>
            <FlexItem>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  onClose();
                  onOpenPolicyTab('security');
                }}
              >
                Security Architecture
              </Button>
            </FlexItem>
            <FlexItem>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  onClose();
                  onOpenPolicyTab('rfcs');
                }}
              >
                RFC Matrix
              </Button>
            </FlexItem>
          </Flex>
        </StackItem>
      </Stack>
    </AboutModal>
  );
}
