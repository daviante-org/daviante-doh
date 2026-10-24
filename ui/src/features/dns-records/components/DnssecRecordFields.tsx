import React from 'react';
import {
  FormGroup,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  TextArea,
  TextInput
} from '@patternfly/react-core';
import { parseIntClamped } from '../../../utils';
import type { LocalRecordData } from '../types/dnsRecords.types';

export type DnssecRecordData = Extract<
  LocalRecordData,
  { type: 'DS' | 'DNSKEY' | 'OPENPGPKEY' | 'CERT' | 'CSYNC' }
>;

export interface DnssecRecordFieldsProps {
  readonly record: DnssecRecordData;
  readonly onUpdateRecord: <T extends LocalRecordData>(updater: (current: T) => T) => void;
}

export function DnssecRecordFields({
  record,
  onUpdateRecord
}: DnssecRecordFieldsProps): React.JSX.Element {
  switch (record.type) {
    case 'DS':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="Key Tag (0-65535)" isRequired fieldId="rdata-ds-keytag">
              <TextInput
                id="rdata-ds-keytag"
                type="number"
                value={record.key_tag}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'DS' }>>((cur) => ({
                    ...cur,
                    key_tag: parseIntClamped(val, 12345, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="DNSSEC Algorithm" isRequired fieldId="rdata-ds-alg">
              <FormSelect
                id="rdata-ds-alg"
                value={record.algorithm}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'DS' }>>((cur) => ({
                    ...cur,
                    algorithm: parseIntClamped(val, 13, 1, 255)
                  })); }
                }
              >
                <FormSelectOption value={8} label="8 — RSASHA256" />
                <FormSelectOption value={13} label="13 — ECDSAP256SHA256" />
                <FormSelectOption value={14} label="14 — ECDSAP384SHA384" />
                <FormSelectOption value={15} label="15 — ED25519" />
                <FormSelectOption value={16} label="16 — ED448" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Digest Type" isRequired fieldId="rdata-ds-digesttype">
              <FormSelect
                id="rdata-ds-digesttype"
                value={record.digest_type}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'DS' }>>((cur) => ({
                    ...cur,
                    digest_type: parseIntClamped(val, 2, 1, 4)
                  })); }
                }
              >
                <FormSelectOption value={1} label="1 — SHA-1 (40 Hex Chars)" />
                <FormSelectOption value={2} label="2 — SHA-256 (64 Hex Chars)" />
                <FormSelectOption value={4} label="4 — SHA-384 (96 Hex Chars)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={12}>
            <FormGroup label="Hexadecimal Digest" isRequired fieldId="rdata-ds-digest">
              <TextInput
                id="rdata-ds-digest"
                value={record.digest}
                maxLength={256}
                spellCheck={false}
                autoComplete="off"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'DS' }>>((cur) => ({
                    ...cur,
                    digest: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'DNSKEY':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="Flags" isRequired fieldId="rdata-dnskey-flags">
              <FormSelect
                id="rdata-dnskey-flags"
                value={record.flags}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'DNSKEY' }>>((cur) => ({
                    ...cur,
                    flags: parseIntClamped(val, 257, 0, 65535)
                  })); }
                }
              >
                <FormSelectOption value={256} label="256 — Zone Signing Key (ZSK)" />
                <FormSelectOption value={257} label="257 — Key Signing Key (KSK / SEP)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Protocol (RFC 4034)" isRequired fieldId="rdata-dnskey-proto">
              <TextInput id="rdata-dnskey-proto" type="number" value={record.protocol} isDisabled />
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Algorithm" isRequired fieldId="rdata-dnskey-alg">
              <FormSelect
                id="rdata-dnskey-alg"
                value={record.algorithm}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'DNSKEY' }>>((cur) => ({
                    ...cur,
                    algorithm: parseIntClamped(val, 13, 1, 255)
                  })); }
                }
              >
                <FormSelectOption value={8} label="8 — RSASHA256" />
                <FormSelectOption value={13} label="13 — ECDSAP256SHA256" />
                <FormSelectOption value={14} label="14 — ECDSAP384SHA384" />
                <FormSelectOption value={15} label="15 — ED25519" />
                <FormSelectOption value={16} label="16 — ED448" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={12}>
            <FormGroup label="Public Key (Base64)" isRequired fieldId="rdata-dnskey-pubkey">
              <TextArea
                id="rdata-dnskey-pubkey"
                value={record.public_key}
                maxLength={4096}
                rows={2}
                spellCheck={false}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'DNSKEY' }>>((cur) => ({
                    ...cur,
                    public_key: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'OPENPGPKEY':
      return (
        <FormGroup
          label="OpenPGP Transferable Public Key Packet (Base64, RFC 7929)"
          isRequired
          fieldId="rdata-openpgpkey"
        >
          <TextArea
            id="rdata-openpgpkey"
            value={record.public_key}
            maxLength={8192}
            rows={3}
            spellCheck={false}
            onChange={(_e, val) =>
              { onUpdateRecord<Extract<LocalRecordData, { type: 'OPENPGPKEY' }>>((cur) => ({
                ...cur,
                public_key: val
              })); }
            }
          />
        </FormGroup>
      );

    case 'CERT':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="Certificate Type" isRequired fieldId="rdata-cert-type">
              <FormSelect
                id="rdata-cert-type"
                value={record.cert_type}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CERT' }>>((cur) => ({
                    ...cur,
                    cert_type: parseIntClamped(val, 1, 0, 65535)
                  })); }
                }
              >
                <FormSelectOption value={1} label="1 — PKIX (X.509)" />
                <FormSelectOption value={2} label="2 — SPKI" />
                <FormSelectOption value={3} label="3 — PGP" />
                <FormSelectOption value={4} label="4 — IPKIX" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Key Tag" isRequired fieldId="rdata-cert-keytag">
              <TextInput
                id="rdata-cert-keytag"
                type="number"
                value={record.key_tag}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CERT' }>>((cur) => ({
                    ...cur,
                    key_tag: parseIntClamped(val, 12345, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Algorithm" isRequired fieldId="rdata-cert-alg">
              <TextInput
                id="rdata-cert-alg"
                type="number"
                value={record.algorithm}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CERT' }>>((cur) => ({
                    ...cur,
                    algorithm: parseIntClamped(val, 13, 0, 255)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={12}>
            <FormGroup label="Certificate Payload (Base64)" isRequired fieldId="rdata-cert-data">
              <TextArea
                id="rdata-cert-data"
                value={record.cert_data}
                maxLength={8192}
                rows={3}
                spellCheck={false}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CERT' }>>((cur) => ({
                    ...cur,
                    cert_data: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'CSYNC':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="SOA Serial" isRequired fieldId="rdata-csync-serial">
              <TextInput
                id="rdata-csync-serial"
                type="number"
                value={record.soa_serial}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CSYNC' }>>((cur) => ({
                    ...cur,
                    soa_serial: parseIntClamped(val, 2026041701, 0, 4294967295)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={3}>
            <FormGroup label="Flags" isRequired fieldId="rdata-csync-flags">
              <FormSelect
                id="rdata-csync-flags"
                value={record.flags}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CSYNC' }>>((cur) => ({
                    ...cur,
                    flags: parseIntClamped(val, 1, 0, 3)
                  })); }
                }
              >
                <FormSelectOption value={0} label="0 — Default" />
                <FormSelectOption value={1} label="1 — Immediate" />
                <FormSelectOption value={2} label="2 — SOA Minimum" />
                <FormSelectOption value={3} label="3 — Immediate + SOA Minimum" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={5}>
            <FormGroup
              label="Synchronized RR Types (space-separated)"
              isRequired
              fieldId="rdata-csync-types"
            >
              <TextInput
                id="rdata-csync-types"
                value={record.types}
                maxLength={256}
                placeholder="A AAAA NS"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CSYNC' }>>((cur) => ({
                    ...cur,
                    types: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );
  }
}
