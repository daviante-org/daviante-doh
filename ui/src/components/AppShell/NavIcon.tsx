import React from 'react';
import {
  BuildingIcon,
  DatabaseIcon,
  DesktopIcon,
  LockIcon,
  SearchIcon,
  ShieldAltIcon,
  TachometerAltIcon
} from '@patternfly/react-icons';
import { assertNever } from '../../utils';
import type { NavIconProps } from './AppShell.types';

export function NavIcon({ name }: NavIconProps): React.JSX.Element {
  switch (name) {
    case 'Database':
      return <DatabaseIcon />;
    case 'Search':
      return <SearchIcon />;
    case 'Shield':
      return <ShieldAltIcon />;
    case 'Tachometer':
      return <TachometerAltIcon />;
    case 'Building':
      return <BuildingIcon />;
    case 'Desktop':
      return <DesktopIcon />;
    case 'Lock':
      return <LockIcon />;
    default:
      return assertNever(name);
  }
}
