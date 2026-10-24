import React from 'react';
import {
  Checkbox,
  FormGroup,
  FormHelperText,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  TextInput
} from '@patternfly/react-core';
import type { LocalRecordData } from '../types/dnsRecords.types';

export type AddressOrAliasRecordData = Extract<
  LocalRecordData,
  { type: 'A' | 'AAAA' | 'CNAME' | 'ANAME' | 'DNAME' | 'PTR' }
>;

export interface AddressRecordFieldsProps {
  readonly record: AddressOrAliasRecordData;
  readonly onUpdateRecord: <T extends LocalRecordData>(updater: (current: T) => T) => void;
}

export function AddressRecordFields({
  record,
  onUpdateRecord
}: AddressRecordFieldsProps): React.JSX.Element {
  switch (record.type) {
    case 'A':
    case 'AAAA':
      return (
        <Grid hasGutter>
          <GridItem md={8}>
            <FormGroup
              label={
                record.type === 'A'
                  ? 'IPv4 Address (RFC 1035)'
                  : 'IPv6 Address (RFC 3596)'
              }
              isRequired
              fieldId="rdata-ip"
            >
              <TextInput
                id="rdata-ip"
                value={record.ip}
                maxLength={45}
                placeholder={record.type === 'A' ? '10.0.0.10' : '2001:db8::10'}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'A' | 'AAAA' }>>((cur) => ({
                    ...cur,
                    ip: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Reverse DNS (PTR)" fieldId="rdata-auto-ptr">
              <Checkbox
                id="rdata-auto-ptr"
                label="Auto-create reverse PTR record (.arpa)"
                isChecked={record.auto_ptr}
                onChange={(_e, checked) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'A' | 'AAAA' }>>((cur) => ({
                    ...cur,
                    auto_ptr: checked
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'CNAME':
    case 'ANAME':
    case 'DNAME':
    case 'PTR':
      return (
        <FormGroup
          label={`Target FQDN (${record.type})`}
          isRequired
          fieldId="rdata-target"
        >
          <TextInput
            id="rdata-target"
            value={record.target}
            maxLength={253}
            placeholder="target.internal.corp"
            onChange={(_e, val) =>
              { onUpdateRecord<
                Extract<LocalRecordData, { type: 'CNAME' | 'ANAME' | 'DNAME' | 'PTR' }>
              >((cur) => ({
                ...cur,
                target: val
              })); }
            }
          />
          <FormHelperText>
            <HelperText>
              <HelperTextItem>
                {record.type === 'CNAME'
                  ? 'RFC 2181 §10.1: A CNAME record cannot coexist with any other record at the same owner name.'
                  : record.type === 'ANAME'
                    ? 'ANAME allows zone-apex aliasing while synthesizing A/AAAA responses.'
                    : 'Enter a fully qualified domain name.'}
              </HelperTextItem>
            </HelperText>
          </FormHelperText>
        </FormGroup>
      );
  }
}
