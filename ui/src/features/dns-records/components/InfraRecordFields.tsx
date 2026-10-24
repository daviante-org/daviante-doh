import React from 'react';
import {
  FormGroup,
  FormHelperText,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  TextInput
} from '@patternfly/react-core';
import { parseIntClamped } from '../../../utils';
import type { LocalRecordData } from '../types/dnsRecords.types';

export type InfraRecordData = Extract<
  LocalRecordData,
  { type: 'NS' | 'SOA' | 'LOC' | 'HINFO' | 'RP' | 'RAW' }
>;

export interface InfraRecordFieldsProps {
  readonly record: InfraRecordData;
  readonly onUpdateRecord: <T extends LocalRecordData>(updater: (current: T) => T) => void;
}

export function InfraRecordFields({
  record,
  onUpdateRecord
}: InfraRecordFieldsProps): React.JSX.Element {
  switch (record.type) {
    case 'NS':
      return (
        <FormGroup label="Target Authoritative Name Server (NS)" isRequired fieldId="rdata-ns">
          <TextInput
            id="rdata-ns"
            value={record.target}
            maxLength={253}
            placeholder="ns1.internal.corp"
            onChange={(_e, val) =>
              { onUpdateRecord<Extract<LocalRecordData, { type: 'NS' }>>((cur) => ({
                ...cur,
                target: val
              })); }
            }
          />
        </FormGroup>
      );

    case 'SOA':
      return (
        <Grid hasGutter>
          <GridItem md={6}>
            <FormGroup label="Primary Nameserver (MNAME)" isRequired fieldId="rdata-soa-mname">
              <TextInput
                id="rdata-soa-mname"
                value={record.mname}
                maxLength={253}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SOA' }>>((cur) => ({
                    ...cur,
                    mname: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="Responsible Mailbox (RNAME)" isRequired fieldId="rdata-soa-rname">
              <TextInput
                id="rdata-soa-rname"
                value={record.rname}
                maxLength={253}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SOA' }>>((cur) => ({
                    ...cur,
                    rname: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Serial" isRequired fieldId="rdata-soa-serial">
              <TextInput
                id="rdata-soa-serial"
                type="number"
                value={record.serial}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SOA' }>>((cur) => ({
                    ...cur,
                    serial: parseIntClamped(val, 2026041701, 0, 4294967295)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Refresh (s)" isRequired fieldId="rdata-soa-refresh">
              <TextInput
                id="rdata-soa-refresh"
                type="number"
                value={record.refresh}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SOA' }>>((cur) => ({
                    ...cur,
                    refresh: parseIntClamped(val, 3600, 1, 2147483647)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Retry (s)" isRequired fieldId="rdata-soa-retry">
              <TextInput
                id="rdata-soa-retry"
                type="number"
                value={record.retry}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SOA' }>>((cur) => ({
                    ...cur,
                    retry: parseIntClamped(val, 600, 1, 2147483647)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Expire (s)" isRequired fieldId="rdata-soa-expire">
              <TextInput
                id="rdata-soa-expire"
                type="number"
                value={record.expire}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SOA' }>>((cur) => ({
                    ...cur,
                    expire: parseIntClamped(val, 604800, 1, 2147483647)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Minimum TTL" isRequired fieldId="rdata-soa-minimum">
              <TextInput
                id="rdata-soa-minimum"
                type="number"
                value={record.minimum}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SOA' }>>((cur) => ({
                    ...cur,
                    minimum: parseIntClamped(val, 300, 0, 4294967295)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'LOC':
      return (
        <FormGroup
          label="Geographical Coordinates (RFC 1876)"
          isRequired
          fieldId="rdata-loc-coords"
        >
          <TextInput
            id="rdata-loc-coords"
            value={record.coordinates}
            maxLength={128}
            placeholder="37 46 29.744 N 122 25 9.816 W 15.00m"
            onChange={(_e, val) =>
              { onUpdateRecord<Extract<LocalRecordData, { type: 'LOC' }>>((cur) => ({
                ...cur,
                coordinates: val
              })); }
            }
          />
        </FormGroup>
      );

    case 'HINFO':
      return (
        <Grid hasGutter>
          <GridItem md={6}>
            <FormGroup label="CPU Architecture" isRequired fieldId="rdata-hinfo-cpu">
              <TextInput
                id="rdata-hinfo-cpu"
                value={record.cpu}
                maxLength={128}
                placeholder="X86-64"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'HINFO' }>>((cur) => ({
                    ...cur,
                    cpu: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="Operating System" isRequired fieldId="rdata-hinfo-os">
              <TextInput
                id="rdata-hinfo-os"
                value={record.os}
                maxLength={128}
                placeholder="LINUX"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'HINFO' }>>((cur) => ({
                    ...cur,
                    os: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'RP':
      return (
        <Grid hasGutter>
          <GridItem md={6}>
            <FormGroup label="Responsible Person Mailbox (MBOX)" isRequired fieldId="rdata-rp-mbox">
              <TextInput
                id="rdata-rp-mbox"
                value={record.mbox}
                maxLength={253}
                placeholder="ops.internal.corp"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'RP' }>>((cur) => ({
                    ...cur,
                    mbox: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="TXT Record Domain Pointer (or '.')" isRequired fieldId="rdata-rp-txt">
              <TextInput
                id="rdata-rp-txt"
                value={record.txt}
                maxLength={253}
                placeholder="info.internal.corp"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'RP' }>>((cur) => ({
                    ...cur,
                    txt: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'RAW':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="IANA RR Type Code (1-65535)" isRequired fieldId="rdata-raw-type">
              <TextInput
                id="rdata-raw-type"
                type="number"
                value={record.rr_type}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'RAW' }>>((cur) => ({
                    ...cur,
                    rr_type: parseIntClamped(val, 65280, 1, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={8}>
            <FormGroup
              label="Wire RDATA Hexadecimal (RFC 3597)"
              isRequired
              fieldId="rdata-raw-hex"
            >
              <TextInput
                id="rdata-raw-hex"
                value={record.rdata_hex}
                maxLength={8192}
                spellCheck={false}
                autoComplete="off"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'RAW' }>>((cur) => ({
                    ...cur,
                    rdata_hex: val
                  })); }
                }
              />
              <FormHelperText>
                <HelperText>
                  <HelperTextItem>
                    Meta/QTYPE codes (0, 41 OPT, 249 TKEY, 250 TSIG, 251 IXFR, 252 AXFR, 255 ANY)
                    are rejected.
                  </HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>
          </GridItem>
        </Grid>
      );
  }
}
