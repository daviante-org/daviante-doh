import React from 'react';
import {
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Content,
  ContentVariants,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Stack,
  StackItem
} from '@patternfly/react-core';
import { APACHE_LICENSE_URL, DAVIANTE_ORG_URL } from '../../constants';
import { isSafeHrefUrl } from '../../utils';

export function TermsTabContent(): React.JSX.Element {
  return (
    <Stack hasGutter className="pf-v6-u-pt-md">
      <StackItem>
        <Card isCompact>
          <CardHeader>
            <CardTitle>1. Daviante Organization Software License & Ownership</CardTitle>
          </CardHeader>
          <CardBody>
            <Content component={ContentVariants.p}>
              <strong>Daviante DoH Server & Control-Plane</strong> is copyright © 2026{' '}
              {isSafeHrefUrl(DAVIANTE_ORG_URL) ? (
                <a href={DAVIANTE_ORG_URL} target="_blank" rel="noopener noreferrer">
                  Daviante Organization
                </a>
              ) : (
                'Daviante Organization'
              )}{' '}
              and distributed under the{' '}
              {isSafeHrefUrl(APACHE_LICENSE_URL) ? (
                <a href={APACHE_LICENSE_URL} target="_blank" rel="noopener noreferrer">
                  Apache License, Version 2.0
                </a>
              ) : (
                'Apache License, Version 2.0'
              )}
              .
            </Content>
          </CardBody>
        </Card>
      </StackItem>
      <StackItem>
        <Card isCompact>
          <CardHeader>
            <CardTitle>2. Authorized Enterprise Operational Use</CardTitle>
          </CardHeader>
          <CardBody>
            <DescriptionList isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Administrative Access</DescriptionListTerm>
                <DescriptionListDescription>
                  Access to this control-plane is restricted to authorized network administrators,
                  security engineers, and auditors provisioned via Local Argon2id credentials or
                  enterprise OpenID Connect (OIDC) Single Sign-On.
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Authoritative & Split-Horizon Zone Integrity</DescriptionListTerm>
                <DescriptionListDescription>
                  Administrators are responsible for ensuring that authoritative zones, local
                  split-horizon overrides, and protective sinkhole policies comply with
                  organizational network governance and applicable telecommunications regulations.
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Audit Trail Accountability</DescriptionListTerm>
                <DescriptionListDescription>
                  All control-plane mutations (zone creation, RRset modifications, protective rule
                  updates, and authentication events) are recorded in the server&apos;s immutable
                  audit trail with principal attribution.
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </StackItem>
    </Stack>
  );
}
