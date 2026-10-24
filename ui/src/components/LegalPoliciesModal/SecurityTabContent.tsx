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
  Stack,
  StackItem
} from '@patternfly/react-core';
import { DAVIANTE_ORG_URL, DAVIANTE_REPO_URL } from '../../constants';
import { isSafeHrefUrl } from '../../utils';

export function SecurityTabContent(): React.JSX.Element {
  return (
    <Stack hasGutter className="pf-v6-u-pt-md">
      <StackItem>
        <Card isCompact>
          <CardHeader>
            <CardTitle>Defense-in-Depth Security Controls (OWASP ASVS v4.0 Level 2)</CardTitle>
          </CardHeader>
          <CardBody>
            <DescriptionList isCompact columnModifier={{ default: '2Col' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Content-Security-Policy (CSP)</DescriptionListTerm>
                <DescriptionListDescription>
                  <code>
                    default-src &apos;self&apos;; script-src &apos;self&apos;; object-src
                    &apos;none&apos;; frame-ancestors &apos;none&apos;
                  </code>
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Password Hashing & Auth</DescriptionListTerm>
                <DescriptionListDescription>
                  Argon2id (<code>m=19 MiB, t=2, p=1</code>) + constant-time token comparison +
                  per-IP rate limiting
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>CSRF & Origin Protection</DescriptionListTerm>
                <DescriptionListDescription>
                  Synchronizer token (<code>X-CSRF-Token</code>) held in memory only + strict{' '}
                  <code>Origin</code> / <code>Sec-Fetch-Site</code> verification
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Role-Based Access Control (RBAC)</DescriptionListTerm>
                <DescriptionListDescription>
                  Server-enforced permissions across <code>SuperAdmin</code>, <code>Admin</code>,
                  and <code>ReadOnly</code> auditor roles
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </StackItem>
      <StackItem>
        <Card isCompact>
          <CardHeader>
            <CardTitle>Coordinated Vulnerability Disclosure (Daviante Security Team)</CardTitle>
          </CardHeader>
          <CardBody>
            If you discover a security vulnerability in Daviante DoH, please report it privately via
            GitHub Security Advisories at{' '}
            {isSafeHrefUrl(DAVIANTE_REPO_URL) ? (
              <a
                href={`${DAVIANTE_REPO_URL}/security/advisories`}
                target="_blank"
                rel="noopener noreferrer"
              >
                daviante-org/daviante-doh Security Advisories
              </a>
            ) : (
              'daviante-org/daviante-doh'
            )}{' '}
            or through the{' '}
            {isSafeHrefUrl(DAVIANTE_ORG_URL) ? (
              <a href={DAVIANTE_ORG_URL} target="_blank" rel="noopener noreferrer">
                Daviante Organization portal
              </a>
            ) : (
              'Daviante Organization portal'
            )}
            . Do not disclose unresolved vulnerabilities in public issue trackers.
          </CardBody>
        </Card>
      </StackItem>
    </Stack>
  );
}
