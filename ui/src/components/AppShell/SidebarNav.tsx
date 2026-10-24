import React, { useContext } from 'react';
import {
  Divider,
  Nav,
  NavExpandable,
  NavItem,
  NavList,
  PageContext
} from '@patternfly/react-core';
import { DAVIANTE_ORG_URL } from '../../constants';
import type { NavigationTab } from '../../types';
import { isSafeHrefUrl } from '../../utils';
import type { SidebarNavProps } from './AppShell.types';

/**
 * Inner navigation component consuming PageContext so mobile drawer auto-closes on navigation
 * (AGENTS.md Rule 4.2).
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
      <NavList>
        <NavItem itemId="records" isActive={activeTab === 'records'}>
          Local DNS Records
        </NavItem>
        <NavItem itemId="policy" isActive={activeTab === 'policy'}>
          Protective DNS Policy
        </NavItem>
        <NavItem itemId="lookup" isActive={activeTab === 'lookup'}>
          Live DNS Lookup Tester
        </NavItem>
        <NavItem itemId="telemetry" isActive={activeTab === 'telemetry'}>
          Telemetry &amp; Audit Log
        </NavItem>

        <Divider component="li" />

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
      </NavList>
    </Nav>
  );
}
