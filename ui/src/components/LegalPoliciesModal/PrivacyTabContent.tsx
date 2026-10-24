import React from 'react';
import {
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Label,
  Stack,
  StackItem
} from '@patternfly/react-core';

export function PrivacyTabContent(): React.JSX.Element {
  return (
    <Stack hasGutter className="pf-v6-u-pt-md">
      <StackItem>
        <Card isCompact>
          <CardHeader>
            <CardTitle>Zero Third-Party Telemetry & Self-Hosted Data Sovereignty</CardTitle>
          </CardHeader>
          <CardBody>
            <DescriptionList isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>No External Phone-Home or Analytics</DescriptionListTerm>
                <DescriptionListDescription>
                  Daviante DoH executes 100% locally within your infrastructure. The control-plane UI
                  and Rust DoH engine never transmit DNS queries, zone records, administrator
                  identities, or usage telemetry to external third-party analytics services.
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>DNS Query Activity Ring-Buffer</DescriptionListTerm>
                <DescriptionListDescription>
                  Recent DNS query logs displayed in the Telemetry Dashboard are bounded in-memory
                  ring-buffers used strictly for real-time operational troubleshooting and protective
                  DNS policy verification.
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Session Cookie Isolation</DescriptionListTerm>
                <DescriptionListDescription>
                  Authentication state is maintained strictly via hardened{' '}
                  <Label isCompact color="blue">
                    __Host-doh_admin_session
                  </Label>{' '}
                  or{' '}
                  <Label isCompact color="blue">
                    doh_admin_session
                  </Label>{' '}
                  <code>HttpOnly; SameSite=Strict</code> cookies. No tokens, credentials, or
                  personally identifiable information (PII) are ever written to{' '}
                  <code>localStorage</code> or <code>sessionStorage</code>.
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </StackItem>
    </Stack>
  );
}
