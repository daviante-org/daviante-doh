import React from 'react';
import {
  LocalDnsRecordsFeature,
  type LocalDnsRecordsFeatureProps
} from '../features/dns-records';

export type LocalDnsRecordsPageProps = LocalDnsRecordsFeatureProps;

export function LocalDnsRecordsPage({
  role
}: LocalDnsRecordsPageProps): React.JSX.Element {
  return <LocalDnsRecordsFeature role={role} />;
}
