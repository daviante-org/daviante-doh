import React from 'react';
import {
  FormGroup,
  FormHelperText,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  TextArea,
  TextInput
} from '@patternfly/react-core';
import { parseIntClamped } from '../../../utils';
import type { LocalRecordData } from '../types/dnsRecords.types';

export type MailOrTextRecordData = Extract<LocalRecordData, { type: 'MX' | 'TXT' | 'SPF' }>;

export interface MailAndTextRecordFieldsProps {
  readonly record: MailOrTextRecordData;
  readonly onUpdateRecord: <T extends LocalRecordData>(updater: (current: T) => T) => void;
}

export function MailAndTextRecordFields({
  record,
  onUpdateRecord
}: MailAndTextRecordFieldsProps): React.JSX.Element {
  switch (record.type) {
    case 'MX':
      return (
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="Priority (0-65535)" isRequired fieldId="rdata-mx-priority">
              <TextInput
                id="rdata-mx-priority"
                type="number"
                value={record.priority}
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'MX' }>>((cur) => ({
                    ...cur,
                    priority: parseIntClamped(val, 10, 0, 65535)
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
          <GridItem md={8}>
            <FormGroup
              label="Mail Server Target (or '.' for Null MX)"
              isRequired
              fieldId="rdata-mx-target"
            >
              <TextInput
                id="rdata-mx-target"
                value={record.target}
                maxLength={253}
                placeholder="mail.internal.corp"
                onChange={(_e, val) =>
                  { onUpdateRecord<Extract<LocalRecordData, { type: 'MX' }>>((cur) => ({
                    ...cur,
                    target: val
                  })); }
                }
              />
            </FormGroup>
          </GridItem>
        </Grid>
      );

    case 'TXT':
    case 'SPF':
      return (
        <FormGroup
          label={
            record.type === 'SPF'
              ? 'SPF Policy String (must start with v=spf1)'
              : 'TXT Content (auto-split into 255-byte wire chunks)'
          }
          isRequired
          fieldId="rdata-txt-content"
        >
          <TextArea
            id="rdata-txt-content"
            value={record.content}
            maxLength={record.type === 'SPF' ? 2048 : 4096}
            rows={3}
            spellCheck={false}
            onChange={(_e, val) =>
              { onUpdateRecord<Extract<LocalRecordData, { type: 'TXT' | 'SPF' }>>((cur) => ({
                ...cur,
                content: val
              })); }
            }
          />
          <FormHelperText>
            <HelperText>
              <HelperTextItem>
                Character count: {record.content.length} (wire chunks:{' '}
                {Math.max(1, Math.ceil(record.content.length / 255))} × ≤255B)
              </HelperTextItem>
            </HelperText>
          </FormHelperText>
        </FormGroup>
      );
  }
}
