import React from 'react';
import {
  ProtectivePolicyFeature,
  type ProtectivePolicyFeatureProps
} from '../features/policy';

export type ProtectivePolicyPageProps = ProtectivePolicyFeatureProps;

export function ProtectivePolicyPage({
  role
}: ProtectivePolicyPageProps): React.JSX.Element {
  return <ProtectivePolicyFeature role={role} />;
}
