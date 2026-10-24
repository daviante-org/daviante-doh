import React, { useState } from 'react';
import {
  Brand,
  Button,
  Flex,
  FlexItem,
  Label,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadLogo,
  MastheadMain,
  MastheadToggle,
  Page,
  PageSidebar,
  PageSidebarBody,
  PageToggleButton,
  SkipToContent,
  Switch,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem
} from '@patternfly/react-core';
import { useDarkTheme } from '../../hooks';
import type { AdminRole } from '../../types';
import { assertNever } from '../../utils';
import { LegalPoliciesModal, type LegalPolicyTab } from '../LegalPoliciesModal';
import { AboutDavianteModal } from './AboutDavianteModal';
import type { AppShellProps } from './AppShell.types';
import { SidebarNav } from './SidebarNav';

function formatRoleBadge(role: AdminRole): { label: string; color: 'blue' | 'green' | 'orange' } {
  switch (role) {
    case 'SuperAdmin':
      return { label: 'SuperAdmin', color: 'orange' };
    case 'Admin':
      return { label: 'Admin', color: 'blue' };
    case 'ReadOnly':
      return { label: 'ReadOnly', color: 'green' };
    default:
      return assertNever(role);
  }
}

export function AppShell({
  activeTab,
  onSelectTab,
  username,
  role,
  authMethod,
  onLogout,
  children
}: AppShellProps): React.JSX.Element {
  const { isDarkTheme, setIsDarkTheme } = useDarkTheme();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [isAboutModalOpen, setIsAboutModalOpen] = useState(false);
  const [isLegalModalOpen, setIsLegalModalOpen] = useState(false);
  const [legalModalInitialTab, setLegalModalInitialTab] = useState<LegalPolicyTab>('terms');

  const roleBadge = formatRoleBadge(role);
  const mainContainerId = 'doh-admin-main-content';

  const openPolicyModal = (tab: LegalPolicyTab): void => {
    setLegalModalInitialTab(tab);
    setIsLegalModalOpen(true);
  };

  const handleLogoutClick = async (): Promise<void> => {
    setIsLoggingOut(true);
    try {
      await onLogout();
    } finally {
      setIsLoggingOut(false);
    }
  };

  const masthead = (
    <Masthead>
      <MastheadMain>
        <MastheadToggle>
          <PageToggleButton aria-label="Global navigation" isHamburgerButton />
        </MastheadToggle>
        <MastheadBrand>
          <MastheadLogo component="span">
            <Flex alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapSm' }}>
              <FlexItem>
                <Brand
                  src={isDarkTheme ? '/logo-dark.svg' : '/logo.svg'}
                  alt="Daviante DoH Control-Plane"
                  heights={{ default: '36px' }}
                />
              </FlexItem>
              <FlexItem>
                <Label isCompact color="blue">
                  RFC 8484 Engine
                </Label>
              </FlexItem>
            </Flex>
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar id="masthead-toolbar" isFullHeight>
          <ToolbarContent>
            <ToolbarGroup align={{ default: 'alignEnd' }} gap={{ default: 'gapSm' }}>
              <ToolbarItem>
                <Switch
                  id="dark-theme-toggle"
                  label="Dark theme"
                  isChecked={isDarkTheme}
                  onChange={(_event, checked) => {
                    setIsDarkTheme(checked);
                  }}
                />
              </ToolbarItem>
              <ToolbarItem>
                <Button
                  variant="plain"
                  size="sm"
                  onClick={() => { openPolicyModal('terms'); }}
                  aria-label="Open Governance and Policies Modal"
                >
                  Policies &amp; Terms
                </Button>
              </ToolbarItem>
              <ToolbarItem>
                <Button
                  variant="plain"
                  size="sm"
                  onClick={() => { setIsAboutModalOpen(true); }}
                  aria-label="About Daviante DoH"
                >
                  About
                </Button>
              </ToolbarItem>
              <ToolbarItem>
                <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                  <FlexItem>
                    <Label color={roleBadge.color} isCompact>
                      {roleBadge.label}
                    </Label>
                  </FlexItem>
                  <FlexItem>
                    <Label isCompact>{authMethod.toUpperCase()}</Label>
                  </FlexItem>
                  <FlexItem>
                    <strong>{username}</strong>
                  </FlexItem>
                </Flex>
              </ToolbarItem>
              <ToolbarItem>
                <Button
                  variant="secondary"
                  size="sm"
                  isLoading={isLoggingOut}
                  isDisabled={isLoggingOut}
                  onClick={() => {
                    void handleLogoutClick();
                  }}
                >
                  Sign out
                </Button>
              </ToolbarItem>
            </ToolbarGroup>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );

  const sidebar = (
    <PageSidebar>
      <PageSidebarBody>
        <SidebarNav
          activeTab={activeTab}
          onSelectTab={onSelectTab}
          onOpenPolicyModal={openPolicyModal}
          onOpenAboutModal={() => { setIsAboutModalOpen(true); }}
        />
      </PageSidebarBody>
    </PageSidebar>
  );

  return (
    <>
      <Page
        masthead={masthead}
        sidebar={sidebar}
        isManagedSidebar
        mainContainerId={mainContainerId}
        skipToContent={
          <SkipToContent href={`#${mainContainerId}`}>Skip to content</SkipToContent>
        }
      >
        {children}
      </Page>

      <AboutDavianteModal
        isOpen={isAboutModalOpen}
        role={role}
        authMethod={authMethod}
        onClose={() => { setIsAboutModalOpen(false); }}
        onOpenPolicyTab={openPolicyModal}
      />

      <LegalPoliciesModal
        isOpen={isLegalModalOpen}
        initialTab={legalModalInitialTab}
        onClose={() => { setIsLegalModalOpen(false); }}
      />
    </>
  );
}
