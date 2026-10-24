import React, { useContext } from 'react';
import {
  Nav,
  NavExpandable,
  NavGroup,
  NavItem,
  PageContext
} from '@patternfly/react-core';
import { DAVIANTE_ORG_URL } from '../../constants';
import type { NavigationTab } from '../../types';
import { isSafeHrefUrl } from '../../utils';
import type { SidebarNavProps } from './AppShell.types';
import { NavIcon } from './NavIcon';

/**
 * Categorized sidebar navigation consuming PageContext so mobile drawer auto-closes on navigation
 * (AGENTS.md Rule 4.2 & Go_Modern/console AppSidebar pattern).
 */
export function SidebarNav({
  activeTab,
  onSelectTab,
  onOpenPolicyModal,
  onOpenAboutModal
}: SidebarNavProps): React.JSX.Element {
  const { isSidebarOpen, onSidebarToggle } = useContext(PageContext);

  const handleSelect = (
    _event: React.FormEvent<HTMLInputElement>,
    result: { itemId: number | string }
  ): void => {
    const id = String(result.itemId);
    if (id === 'records' || id === 'policy' || id === 'lookup' || id === 'telemetry') {
      onSelectTab(id as NavigationTab);
      if (window.innerWidth < 1200 && isSidebarOpen) {
        onSidebarToggle();
      }
    }
  };

  return (
    <Nav onSelect={handleSelect} aria-label="Daviante DoH Admin Primary Navigation">
      <NavGroup title="DNS Authority & Resolution">
        <NavItem
          itemId="records"
          isActive={activeTab === 'records'}
          icon={<NavIcon name="Database" />}
        >
          Local DNS Records
        </NavItem>
        <NavItem
          itemId="lookup"
          isActive={activeTab === 'lookup'}
          icon={<NavIcon name="Search" />}
        >
          Live DNS Lookup Tester
        </NavItem>
      </NavGroup>

      <NavGroup title="Security & Threat Defense">
        <NavItem
          itemId="policy"
          isActive={activeTab === 'policy'}
          icon={<NavIcon name="Shield" />}
        >
          Protective DNS Policy
        </NavItem>
      </NavGroup>

      <NavGroup title="Observability & Governance">
        <NavItem
          itemId="telemetry"
          isActive={activeTab === 'telemetry'}
          icon={<NavIcon name="Tachometer" />}
        >
          Telemetry &amp; Audit Log
        </NavItem>

        <NavExpandable
          title="Governance & Compliance"
          groupId="nav-governance-group"
          isExpanded={false}
        >
          <NavItem
            itemId="gov-terms"
            onClick={(e) => {
              e.preventDefault();
              onOpenPolicyModal('terms');
            }}
          >
            Terms of Service &amp; License
          </NavItem>
          <NavItem
            itemId="gov-privacy"
            onClick={(e) => {
              e.preventDefault();
              onOpenPolicyModal('privacy');
            }}
          >
            Data Privacy Policy
          </NavItem>
          <NavItem
            itemId="gov-security"
            onClick={(e) => {
              e.preventDefault();
              onOpenPolicyModal('security');
            }}
          >
            Security Architecture
          </NavItem>
          <NavItem
            itemId="gov-rfcs"
            onClick={(e) => {
              e.preventDefault();
              onOpenPolicyModal('rfcs');
            }}
          >
            RFC Compliance Matrix
          </NavItem>
          <NavItem
            itemId="gov-about"
            onClick={(e) => {
              e.preventDefault();
              onOpenAboutModal();
            }}
          >
            About Daviante DoH
          </NavItem>
          {isSafeHrefUrl(DAVIANTE_ORG_URL) && (
            <NavItem
              itemId="gov-github"
              to={DAVIANTE_ORG_URL}
              target="_blank"
              rel="noopener noreferrer"
            >
              Daviante Organization ↗
            </NavItem>
          )}
        </NavExpandable>
      </NavGroup>
    </Nav>
  );
}
