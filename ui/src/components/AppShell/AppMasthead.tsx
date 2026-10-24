import React from 'react';
import {
  Brand,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadLogo,
  MastheadMain,
  MastheadToggle,
  PageToggleButton,
  ToggleGroup,
  ToggleGroupItem,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem
} from '@patternfly/react-core';
import { MoonIcon, SunIcon } from '@patternfly/react-icons';
import type { AppMastheadProps } from './AppShell.types';
import { UserMenuDropdown } from './UserMenuDropdown';

export function AppMasthead({
  isDarkTheme,
  onSetDarkTheme,
  username,
  role,
  authMethod,
  isLoggingOut,
  onOpenPolicyModal,
  onOpenAboutModal,
  onLogout
}: AppMastheadProps): React.JSX.Element {
  return (
    <Masthead id="app-masthead">
      <MastheadMain>
        <MastheadToggle>
          <PageToggleButton
            isHamburgerButton
            aria-label="Global navigation"
            id="vertical-nav-toggle"
          />
        </MastheadToggle>
        <MastheadBrand data-codemods>
          <MastheadLogo component="span">
            <Brand
              src={isDarkTheme ? '/logo-dark.svg' : '/logo.svg'}
              alt="Daviante DoH Control-Plane"
              heights={{ default: '36px' }}
            />
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>

      <MastheadContent>
        <Toolbar id="masthead-toolbar" isFullHeight isStatic>
          <ToolbarContent>
            <ToolbarGroup
              variant="action-group-plain"
              align={{ default: 'alignEnd' }}
            >
              <ToolbarItem alignSelf="center">
                <ToggleGroup aria-label="Dark theme toggle">
                  <ToggleGroupItem
                    icon={<SunIcon />}
                    aria-label="Light theme"
                    isSelected={!isDarkTheme}
                    onChange={() => {
                      onSetDarkTheme(false);
                    }}
                  />
                  <ToggleGroupItem
                    icon={<MoonIcon />}
                    aria-label="Dark theme"
                    isSelected={isDarkTheme}
                    onChange={() => {
                      onSetDarkTheme(true);
                    }}
                  />
                </ToggleGroup>
              </ToolbarItem>

              <ToolbarItem>
                <UserMenuDropdown
                  username={username}
                  role={role}
                  authMethod={authMethod}
                  isLoggingOut={isLoggingOut}
                  onOpenPolicyModal={onOpenPolicyModal}
                  onOpenAboutModal={onOpenAboutModal}
                  onLogout={onLogout}
                />
              </ToolbarItem>
            </ToolbarGroup>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );
}
