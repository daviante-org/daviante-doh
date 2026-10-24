import React, { useState } from 'react';
import {
  Avatar,
  Divider,
  Dropdown,
  DropdownGroup,
  DropdownItem,
  DropdownList,
  MenuToggle
} from '@patternfly/react-core';
import {
  BuildingIcon,
  DesktopIcon,
  ShieldAltIcon,
  SignOutAltIcon
} from '@patternfly/react-icons';
import type { UserMenuDropdownProps } from './AppShell.types';

export function UserMenuDropdown({
  username,
  role,
  authMethod,
  isLoggingOut,
  onOpenPolicyModal,
  onOpenAboutModal,
  onLogout
}: UserMenuDropdownProps): React.JSX.Element {
  const [isOpen, setIsOpen] = useState<boolean>(false);

  return (
    <Dropdown
      isOpen={isOpen}
      onSelect={() => {
        setIsOpen(false);
      }}
      onOpenChange={(open: boolean) => {
        setIsOpen(open);
      }}
      popperProps={{ position: 'right' }}
      toggle={(toggleRef) => (
        <MenuToggle
          ref={toggleRef}
          onClick={() => {
            setIsOpen((prev) => !prev);
          }}
          isExpanded={isOpen}
          isFullHeight
          icon={<Avatar src="/favicon.svg" alt="" size="sm" />}
        >
          {username}
        </MenuToggle>
      )}
    >
      <DropdownGroup label={`${username} (${role} • ${authMethod.toUpperCase()})`}>
        <DropdownList>
          <DropdownItem
            key="policies-terms"
            icon={<BuildingIcon />}
            onClick={() => {
              onOpenPolicyModal('terms');
            }}
          >
            Policies &amp; Terms
          </DropdownItem>
          <DropdownItem
            key="rfc-compliance"
            icon={<ShieldAltIcon />}
            onClick={() => {
              onOpenPolicyModal('rfcs');
            }}
          >
            RFC Compliance Matrix
          </DropdownItem>
          <DropdownItem
            key="about-daviante"
            icon={<DesktopIcon />}
            onClick={onOpenAboutModal}
          >
            About Daviante DoH
          </DropdownItem>
          <Divider component="li" />
          <DropdownItem
            key="sign-out"
            icon={<SignOutAltIcon />}
            isDisabled={isLoggingOut}
            onClick={() => {
              void onLogout();
            }}
          >
            Sign out
          </DropdownItem>
        </DropdownList>
      </DropdownGroup>
    </Dropdown>
  );
}
