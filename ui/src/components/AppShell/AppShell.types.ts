import type React from 'react';
import type { AdminRole, NavigationTab } from '../../types';
import type { LegalPolicyTab } from '../LegalPoliciesModal';

export type { NavigationTab };

export interface AppShellProps {
  readonly activeTab: NavigationTab;
  readonly onSelectTab: (tab: NavigationTab) => void;
  readonly username: string;
  readonly role: AdminRole;
  readonly authMethod: string;
  readonly onLogout: () => Promise<void>;
  readonly children: React.ReactNode;
}

export interface SidebarNavProps {
  readonly activeTab: NavigationTab;
  readonly onSelectTab: (tab: NavigationTab) => void;
  readonly onOpenPolicyModal: (tab: LegalPolicyTab) => void;
  readonly onOpenAboutModal: () => void;
}

export interface AboutDavianteModalProps {
  readonly isOpen: boolean;
  readonly role: AdminRole;
  readonly authMethod: string;
  readonly onClose: () => void;
  readonly onOpenPolicyTab: (tab: LegalPolicyTab) => void;
}
