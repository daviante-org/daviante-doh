import React, { Suspense, lazy, useState } from 'react';
import {
  Alert,
  Bullseye,
  Button,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  PageSection,
  Spinner
} from '@patternfly/react-core';
import { AppShell, type NavigationTab } from '../components';
import { LoginView, useAuthSession } from '../features/auth';
import { LocalDnsRecordsPage } from '../pages/LocalDnsRecordsPage';
import { assertNever } from '../utils';

const ProtectivePolicyPage = lazy(async () => {
  const mod = await import('../pages/ProtectivePolicyPage');
  return { default: mod.ProtectivePolicyPage };
});

const DnsLookupTesterPage = lazy(async () => {
  const mod = await import('../pages/DnsLookupTesterPage');
  return { default: mod.DnsLookupTesterPage };
});

const TelemetryDashboardPage = lazy(async () => {
  const mod = await import('../pages/TelemetryDashboardPage');
  return { default: mod.TelemetryDashboardPage };
});

export function App(): React.JSX.Element {
  const { authState, refreshSession, handleLoginLocal, handleLogout } = useAuthSession();
  const [activeTab, setActiveTab] = useState<NavigationTab>('records');

  const renderActivePage = (): React.JSX.Element => {
    if (authState.status !== 'authenticated') {
      return <></>;
    }
    switch (activeTab) {
      case 'records':
        return <LocalDnsRecordsPage role={authState.role} />;
      case 'policy':
        return <ProtectivePolicyPage role={authState.role} />;
      case 'lookup':
        return <DnsLookupTesterPage />;
      case 'telemetry':
        return <TelemetryDashboardPage />;
      default:
        return assertNever(activeTab);
    }
  };

  switch (authState.status) {
    case 'loading':
      return (
        <Bullseye>
          <EmptyState titleText="Initializing DoH Control-Plane" headingLevel="h2" icon={Spinner}>
            <EmptyStateBody>Verifying session and security policy...</EmptyStateBody>
          </EmptyState>
        </Bullseye>
      );

    case 'error':
      return (
        <PageSection isFilled>
          <EmptyState titleText="Unable to connect to DoH Admin API" headingLevel="h2">
            <EmptyStateBody>
              <Alert variant="danger" isInline title={authState.message} />
            </EmptyStateBody>
            <EmptyStateFooter>
              <EmptyStateActions>
                <Button variant="primary" onClick={() => void refreshSession()}>
                  Retry Connection
                </Button>
              </EmptyStateActions>
            </EmptyStateFooter>
          </EmptyState>
        </PageSection>
      );

    case 'unauthenticated':
      return (
        <LoginView
          localAuthEnabled={authState.localAuthEnabled}
          oidcEnabled={authState.oidcEnabled}
          oidcProviderName={authState.oidcProviderName}
          onLoginLocal={handleLoginLocal}
        />
      );

    case 'authenticated':
      return (
        <AppShell
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          username={authState.username}
          role={authState.role}
          authMethod={authState.authMethod}
          onLogout={handleLogout}
        >
          <Suspense
            fallback={
              <Bullseye>
                <Spinner size="xl" aria-label="Loading module" />
              </Bullseye>
            }
          >
            {renderActivePage()}
          </Suspense>
        </AppShell>
      );

    default:
      return assertNever(authState);
  }
}
