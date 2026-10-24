import React from 'react';
import {
  FormGroup,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  TextInput
} from '@patternfly/react-core';
import { parseIntClamped } from '../../../utils';
import type { LocalRecordData } from '../types/dnsRecords.types';

export type CertificateRecordData = Extract<
  LocalRecordData,
  { type: 'CAA' | 'TLSA' | 'SMIMEA' | 'SSHFP' }
>;

export interface CertificateRecordFieldsProps {
  readonly record: CertificateRecordData;
  readonly onUpdateRecord: <T extends LocalRecordData>(updater: (current: T) => T) => void;
}

export function CertificateRecordFields({
  record,
  onUpdateRecord
}: CertificateRecordFieldsProps): React.JSX.Element {
  switch (record.type) {
    case 'CAA':
      return (
        <Grid hasGutter>
          <GridItem md={3}>
            <FormGroup label="Flags" isRequired fieldId="rdata-caa-flags">
              <FormSelect
                id="rdata-caa-flags"
                value={record.flags}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CAA' }>>((cur) => ({
                    ...cur,
                    flags: parseIntClamped(val, 0, 0, 255)
                  })); }
                }
              >
                <FormSelectOption value={0} label="0 (Non-critical)" />
                <FormSelectOption value={128} label="128 (Issuer Critical)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={3}>
            <FormGroup label="Property Tag" isRequired fieldId="rdata-caa-tag">
              <FormSelect
                id="rdata-caa-tag"
                value={record.tag}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CAA' }>>((cur) => ({
                    ...cur,
                    tag: val
                  })); }
                }
              >
                <FormSelectOption value="issue" label="issue (Allow CA)" />
                <FormSelectOption value="issuewild" label="issuewild (Allow Wildcard CA)" />
                <FormSelectOption value="iodef" label="iodef (Incident Reporting URI)" />
                <FormSelectOption value="contactemail" label="contactemail (Contact Email)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={6}>
            <FormGroup label="CA Domain / Value" isRequired fieldId="rdata-caa-value">
              <TextInput
                id="rdata-caa-value"
                value={record.value}
                maxLength={512}
                placeholder="letsencrypt.org"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'CAA' }>>((cur) => ({
                    ...cur,
                    value: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'TLSA':
    case 'SMIMEA':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="Certificate Usage" isRequired fieldId="rdata-tlsa-usage">
              <FormSelect
                id="rdata-tlsa-usage"
                value={record.usage}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'TLSA' | 'SMIMEA' }>>((cur) => ({
                    ...cur,
                    usage: parseIntClamped(val, 3, 0, 3)
                  })); }
                }
              >
                <FormSelectOption value={0} label="0 — PKIX-TA (CA Constraint)" />
                <FormSelectOption value={1} label="1 — PKIX-EE (Service Cert Constraint)" />
                <FormSelectOption value={2} label="2 — DANE-TA (Trust Anchor Assertion)" />
                <FormSelectOption value={3} label="3 — DANE-EE (Domain-Issued Cert)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Selector" isRequired fieldId="rdata-tlsa-selector">
              <FormSelect
                id="rdata-tlsa-selector"
                value={record.selector}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'TLSA' | 'SMIMEA' }>>((cur) => ({
                    ...cur,
                    selector: parseIntClamped(val, 1, 0, 1)
                  })); }
                }
              >
                <FormSelectOption value={0} label="0 — Full Certificate" />
                <FormSelectOption value={1} label="1 — SubjectPublicKeyInfo (SPKI)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Matching Type" isRequired fieldId="rdata-tlsa-matching">
              <FormSelect
                id="rdata-tlsa-matching"
                value={record.matching_type}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'TLSA' | 'SMIMEA' }>>((cur) => ({
                    ...cur,
                    matching_type: parseIntClamped(val, 1, 0, 2)
                  })); }
                }
              >
                <FormSelectOption value={0} label="0 — Exact Match (Full Hex)" />
                <FormSelectOption value={1} label="1 — SHA-256 Digest (64 Hex Chars)" />
                <FormSelectOption value={2} label="2 — SHA-512 Digest (128 Hex Chars)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={12}>
            <FormGroup
              label="Certificate Association Data (Hex)"
              isRequired
              fieldId="rdata-tlsa-data"
            >
              <TextInput
                id="rdata-tlsa-data"
                value={record.cert_data}
                maxLength={4096}
                spellCheck={false}
                autoComplete="off"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'TLSA' | 'SMIMEA' }>>((cur) => ({
                    ...cur,
                    cert_data: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'SSHFP':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="Public Key Algorithm" isRequired fieldId="rdata-sshfp-alg">
              <FormSelect
                id="rdata-sshfp-alg"
                value={record.algorithm}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SSHFP' }>>((cur) => ({
                    ...cur,
                    algorithm: parseIntClamped(val, 4, 1, 6)
                  })); }
                }
              >
                <FormSelectOption value={1} label="1 — RSA" />
                <FormSelectOption value={2} label="2 — DSA" />
                <FormSelectOption value={3} label="3 — ECDSA" />
                <FormSelectOption value={4} label="4 — Ed25519" />
                <FormSelectOption value={6} label="6 — Ed448" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Fingerprint Type" isRequired fieldId="rdata-sshfp-fptype">
              <FormSelect
                id="rdata-sshfp-fptype"
                value={record.fp_type}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SSHFP' }>>((cur) => ({
                    ...cur,
                    fp_type: parseIntClamped(val, 2, 1, 2)
                  })); }
                }
              >
                <FormSelectOption value={1} label="1 — SHA-1 (40 Hex Chars)" />
                <FormSelectOption value={2} label="2 — SHA-256 (64 Hex Chars)" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={12}>
            <FormGroup label="Hexadecimal Fingerprint" isRequired fieldId="rdata-sshfp-fp">
              <TextInput
                id="rdata-sshfp-fp"
                value={record.fingerprint}
                maxLength={256}
                spellCheck={false}
                autoComplete="off"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'SSHFP' }>>((cur) => ({
                    ...cur,
                    fingerprint: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );
  }
}
