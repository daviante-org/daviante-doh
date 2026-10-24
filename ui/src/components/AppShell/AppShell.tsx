import React, { useState } from 'react';
import {
  Page,
  PageSidebar,
  PageSidebarBody,
  SkipToContent
} from '@patternfly/react-core';
import { useDarkTheme } from '../../hooks';
import { LegalPoliciesModal, type LegalPolicyTab } from '../LegalPoliciesModal';
import { AboutDavianteModal } from './AboutDavianteModal';
import { AppBreadcrumb } from './AppBreadcrumb';
import { AppMasthead } from './AppMasthead';
import type { AppShellProps } from './AppShell.types';
import { SidebarNav } from './SidebarNav';

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

  const mainContainerId = 'doh-admin-main-content';
  const pageBackground = isDarkTheme ? '/page-bg-dark.svg' : '/page-bg-light.svg';

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

  const sidebar = (
    <PageSidebar id="app-sidebar">
      <PageSidebarBody>
        <SidebarNav
          activeTab={activeTab}
          onSelectTab={onSelectTab}
          onOpenPolicyModal={openPolicyModal}
          onOpenAboutModal={() => {
            setIsAboutModalOpen(true);
          }}
        />
      </PageSidebarBody>
    </PageSidebar>
  );

  return (
    <>
      <Page
        id="app-page-shell"
        mainContainerId={mainContainerId}
        style={
          {
            '--pf-v6-c-page__main-container--BackgroundColor': `url('${pageBackground}') bottom right / cover no-repeat, var(--pf-t--global--background--color--primary--default)`,
            '--pf-v6-c-page__main-section--BackgroundColor': 'transparent',
            '--pf-v6-c-page__main-breadcrumb--BackgroundColor': 'transparent'
          } as React.CSSProperties
        }
        masthead={
          <AppMasthead
            isDarkTheme={isDarkTheme}
            onSetDarkTheme={setIsDarkTheme}
            username={username}
            role={role}
            authMethod={authMethod}
            isLoggingOut={isLoggingOut}
            onOpenPolicyModal={openPolicyModal}
            onOpenAboutModal={() => {
              setIsAboutModalOpen(true);
            }}
            onLogout={handleLogoutClick}
          />
        }
        sidebar={sidebar}
        breadcrumb={
          <AppBreadcrumb activeTab={activeTab} onSelectTab={onSelectTab} />
        }
        skipToContent={
          <SkipToContent href={`#${mainContainerId}`}>Skip to content</SkipToContent>
        }
        isManagedSidebar
        defaultManagedSidebarIsOpen={true}
        isContentFilled
      >
        {children}
      </Page>

      <AboutDavianteModal
        isOpen={isAboutModalOpen}
        role={role}
        authMethod={authMethod}
        onClose={() => {
          setIsAboutModalOpen(false);
        }}
        onOpenPolicyTab={openPolicyModal}
      />

      <LegalPoliciesModal
        isOpen={isLegalModalOpen}
        initialTab={legalModalInitialTab}
        onClose={() => {
          setIsLegalModalOpen(false);
        }}
      />
    </>
  );
}
