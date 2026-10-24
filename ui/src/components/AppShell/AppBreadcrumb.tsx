import React from 'react';
import { Breadcrumb, BreadcrumbItem } from '@patternfly/react-core';
import type { NavigationTab } from '../../types';
import { assertNever } from '../../utils';
import type { AppBreadcrumbProps } from './AppShell.types';

function resolveBreadcrumbMeta(tab: NavigationTab): { group: string; page: string } {
  switch (tab) {
    case 'records':
      return { group: 'DNS Authority & Resolution', page: 'Local DNS Records' };
    case 'lookup':
      return { group: 'DNS Authority & Resolution', page: 'Live DNS Lookup Tester' };
    case 'policy':
      return { group: 'Security & Threat Defense', page: 'Protective DNS Policy' };
    case 'telemetry':
      return { group: 'Observability & Governance', page: 'Telemetry & Audit Log' };
    default:
      return assertNever(tab);
  }
}

export function AppBreadcrumb({
  activeTab,
  onSelectTab
}: AppBreadcrumbProps): React.JSX.Element {
  const meta = resolveBreadcrumbMeta(activeTab);

  return (
    <Breadcrumb>
      <BreadcrumbItem
        to="#records"
        onClick={(event) => {
          event.preventDefault();
          onSelectTab('records');
        }}
      >
        Home
      </BreadcrumbItem>
      <BreadcrumbItem>{meta.group}</BreadcrumbItem>
      <BreadcrumbItem isActive>{meta.page}</BreadcrumbItem>
    </Breadcrumb>
  );
}
