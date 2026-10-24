import React from 'react';
import {
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  TextInput
} from '@patternfly/react-core';
import { parseIntClamped } from '../../../utils';
import type { LocalRecordData } from '../types/dnsRecords.types';

export type ServiceDiscoveryRecordData = Extract<
  LocalRecordData,
  { type: 'SRV' | 'HTTPS' | 'SVCB' | 'NAPTR' | 'URI' }
>;

export interface ServiceRecordFieldsProps {
  readonly record: ServiceDiscoveryRecordData;
  readonly onUpdateRecord: <T extends LocalRecordData>(updater: (current: T) => T) => void;
}

export function ServiceRecordFields({
  record,
  onUpdateRecord
}: ServiceRecordFieldsProps): React.JSX.Element {
  switch (record.type) {
    case 'SRV':
      return (
        <Grid hasGutter>
          <GridItem md={2}>
            <FormGroup label="Priority" isRequired fieldId="rdata-srv-priority">
              <TextInput
                id="rdata-srv-priority"
                type="number"
                value={record.priority}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SRV' }>>((cur) => ({
                    ...cur,
                    priority: parseIntClamped(val, 10, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Weight" isRequired fieldId="rdata-srv-weight">
              <TextInput
                id="rdata-srv-weight"
                type="number"
                value={record.weight}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SRV' }>>((cur) => ({
                    ...cur,
                    weight: parseIntClamped(val, 5, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Port" isRequired fieldId="rdata-srv-port">
              <TextInput
                id="rdata-srv-port"
                type="number"
                value={record.port}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SRV' }>>((cur) => ({
                    ...cur,
                    port: parseIntClamped(val, 443, 1, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="Target Host" isRequired fieldId="rdata-srv-target">
              <TextInput
                id="rdata-srv-target"
                value={record.target}
                maxLength={253}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SRV' }>>((cur) => ({
                    ...cur,
                    target: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'HTTPS':
    case 'SVCB':
      return (
        <Grid hasGutter>
          <GridItem md={3}>
            <FormGroup
              label="SvcPriority (0 = AliasMode)"
              isRequired
              fieldId="rdata-svcb-priority"
            >
              <TextInput
                id="rdata-svcb-priority"
                type="number"
                value={record.priority}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'HTTPS' | 'SVCB' }>>((cur) => ({
                    ...cur,
                    priority: parseIntClamped(val, 1, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="TargetName (or '.')" isRequired fieldId="rdata-svcb-target">
              <TextInput
                id="rdata-svcb-target"
                value={record.target}
                maxLength={253}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'HTTPS' | 'SVCB' }>>((cur) => ({
                    ...cur,
                    target: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={5}>
            <FormGroup label="SvcParams (RFC 9460)" fieldId="rdata-svcb-params">
              <TextInput
                id="rdata-svcb-params"
                value={record.svc_params}
                maxLength={1024}
                placeholder='alpn="h3,h2" ipv4hint=10.0.0.10'
                spellCheck={false}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'HTTPS' | 'SVCB' }>>((cur) => ({
                    ...cur,
                    svc_params: val
                  })); }
                }
              />
              <FormHelperText>
                <HelperText>
                  <HelperTextItem>
                    Supported keys: alpn, no-default-alpn, port, ipv4hint, ipv6hint, ech, mandatory,
                    dohpath, keyNNNN
                  </HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'NAPTR':
      return (
        <Grid hasGutter>
          <GridItem md={2}>
            <FormGroup label="Order" isRequired fieldId="rdata-naptr-order">
              <TextInput
                id="rdata-naptr-order"
                type="number"
                value={record.order}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'NAPTR' }>>((cur) => ({
                    ...cur,
                    order: parseIntClamped(val, 100, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Preference" isRequired fieldId="rdata-naptr-pref">
              <TextInput
                id="rdata-naptr-pref"
                type="number"
                value={record.preference}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'NAPTR' }>>((cur) => ({
                    ...cur,
                    preference: parseIntClamped(val, 10, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Flags" fieldId="rdata-naptr-flags">
              <FormSelect
                id="rdata-naptr-flags"
                value={record.flags}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'NAPTR' }>>((cur) => ({
                    ...cur,
                    flags: val
                  })); }
                }
              >
                <FormSelectOption value="S" label="S (SRV Lookup)" />
                <FormSelectOption value="A" label="A (Address Lookup)" />
                <FormSelectOption value="U" label="U (URI Output)" />
                <FormSelectOption value="P" label="P (Protocol Specific)" />
                <FormSelectOption value="" label="(Empty / Non-terminal)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="Service Parameters" fieldId="rdata-naptr-service">
              <TextInput
                id="rdata-naptr-service"
                value={record.service}
                maxLength={128}
                placeholder="SIP+D2U"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'NAPTR' }>>((cur) => ({
                    ...cur,
                    service: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="Substitution Regexp" fieldId="rdata-naptr-regexp">
              <TextInput
                id="rdata-naptr-regexp"
                value={record.regexp}
                maxLength={256}
                placeholder="!^.*$!sip:info@example.com!"
                spellCheck={false}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'NAPTR' }>>((cur) => ({
                    ...cur,
                    regexp: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="Replacement Target (or '.')" isRequired fieldId="rdata-naptr-repl">
              <TextInput
                id="rdata-naptr-repl"
                value={record.replacement}
                maxLength={253}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'NAPTR' }>>((cur) => ({
                    ...cur,
                    replacement: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'URI':
      return (
        <Grid hasGutter>
          <GridItem md={2}>
            <FormGroup label="Priority" isRequired fieldId="rdata-uri-priority">
              <TextInput
                id="rdata-uri-priority"
                type="number"
                value={record.priority}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'URI' }>>((cur) => ({
                    ...cur,
                    priority: parseIntClamped(val, 10, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={2}>
            <FormGroup label="Weight" isRequired fieldId="rdata-uri-weight">
              <TextInput
                id="rdata-uri-weight"
                type="number"
                value={record.weight}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'URI' }>>((cur) => ({
                    ...cur,
                    weight: parseIntClamped(val, 1, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={8}>
            <FormGroup label="Target URI (RFC 7553)" isRequired fieldId="rdata-uri-target">
              <TextInput
                id="rdata-uri-target"
                value={record.target}
                maxLength={1024}
                placeholder="https://svc.internal.corp/api"
                spellCheck={false}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'URI' }>>((cur) => ({
                    ...cur,
                    target: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );
  }
}
