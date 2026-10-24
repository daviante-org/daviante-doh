import type React from 'react';
import type { AdminRole, NavigationTab } from '../../types';
import type { LegalPolicyTab } from '../LegalPoliciesModal';

export type { NavigationTab };

export type NavIconName =
  | 'Database'
  | 'Search'
  | 'Shield'
  | 'Tachometer'
  | 'Building'
  | 'Desktop'
  | 'Lock';

export interface NavIconProps {
  readonly name: NavIconName;
}

export interface AppShellProps {
  readonly activeTab: NavigationTab;
  readonly onSelectTab: (tab: NavigationTab) => void;
  readonly username: string;
  readonly role: AdminRole;
  readonly authMethod: string;
  readonly onLogout: () => Promise<void>;
  readonly children: React.ReactNode;
}

export interface AppMastheadProps {
  readonly isDarkTheme: boolean;
  readonly onSetDarkTheme: (isDark: boolean) => void;
  readonly username: string;
  readonly role: AdminRole;
  readonly authMethod: string;
  readonly isLoggingOut: boolean;
  readonly onOpenPolicyModal: (tab: LegalPolicyTab) => void;
  readonly onOpenAboutModal: () => void;
  readonly onLogout: () => Promise<void>;
}

export interface UserMenuDropdownProps {
  readonly username: string;
  readonly role: AdminRole;
  readonly authMethod: string;
  readonly isLoggingOut: boolean;
  readonly onOpenPolicyModal: (tab: LegalPolicyTab) => void;
  readonly onOpenAboutModal: () => void;
  readonly onLogout: () => Promise<void>;
}

export interface AppBreadcrumbProps {
  readonly activeTab: NavigationTab;
  readonly onSelectTab: (tab: NavigationTab) => void;
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
