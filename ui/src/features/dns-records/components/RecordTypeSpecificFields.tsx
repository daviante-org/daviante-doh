import React from 'react';
import { assertNever } from '../../../utils';
import type { LocalRecordData } from '../types/dnsRecords.types';
import { AddressRecordFields } from './AddressRecordFields';
import { CertificateRecordFields } from './CertificateRecordFields';
import { DnssecRecordFields } from './DnssecRecordFields';
import { InfraRecordFields } from './InfraRecordFields';
import { MailAndTextRecordFields } from './MailAndTextRecordFields';
import { ServiceRecordFields } from './ServiceRecordFields';

export interface RecordTypeSpecificFieldsProps {
  readonly record: LocalRecordData;
  readonly onUpdateRecord: <T extends LocalRecordData>(updater: (current: T) => T) => void;
}

export function RecordTypeSpecificFields({
  record,
  onUpdateRecord
}: RecordTypeSpecificFieldsProps): React.JSX.Element {
  switch (record.type) {
    case 'A':
    case 'AAAA':
    case 'CNAME':
    case 'ANAME':
    case 'DNAME':
    case 'PTR':
      return <AddressRecordFields record={record} onUpdateRecord={onUpdateRecord} />;

    case 'MX':
    case 'TXT':
    case 'SPF':
      return <MailAndTextRecordFields record={record} onUpdateRecord={onUpdateRecord} />;

    case 'SRV':
    case 'HTTPS':
    case 'SVCB':
    case 'NAPTR':
    case 'URI':
      return <ServiceRecordFields record={record} onUpdateRecord={onUpdateRecord} />;

    case 'CAA':
    case 'TLSA':
    case 'SMIMEA':
    case 'SSHFP':
      return <CertificateRecordFields record={record} onUpdateRecord={onUpdateRecord} />;

    case 'DS':
    case 'DNSKEY':
    case 'OPENPGPKEY':
    case 'CERT':
    case 'CSYNC':
      return <DnssecRecordFields record={record} onUpdateRecord={onUpdateRecord} />;

    case 'NS':
    case 'SOA':
    case 'LOC':
    case 'HINFO':
    case 'RP':
    case 'RAW':
      return <InfraRecordFields record={record} onUpdateRecord={onUpdateRecord} />;

    default:
      return assertNever(record);
  }
}
