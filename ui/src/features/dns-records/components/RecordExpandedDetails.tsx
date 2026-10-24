import React from 'react';
import {
  ClipboardCopy,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Grid,
  GridItem
} from '@patternfly/react-core';
import { ExpandableRowContent } from '@patternfly/react-table';
import { formatUpdatedEpoch } from '../../../utils';
import type { LocalDnsRecordView } from '../types/dnsRecords.types';
import { getRecordRdataBreakdown } from '../utils/recordFormatters';

export interface RecordExpandedDetailsProps {
  readonly item: LocalDnsRecordView;
}

export function RecordExpandedDetails({
  item
}: RecordExpandedDetailsProps): React.JSX.Element {
  const rdataPairs = getRecordRdataBreakdown(item.record);

  return (
    <ExpandableRowContent>
      <Grid hasGutter>
        <GridItem md={7}>
          <DescriptionList isCompact isHorizontal columnModifier={{ default: '2Col' }}>
            <DescriptionListGroup>
              <DescriptionListTerm>Canonical FQDN</DescriptionListTerm>
              <DescriptionListDescription>
                <code>{item.domain}.</code>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>IANA RR Type Code</DescriptionListTerm>
              <DescriptionListDescription>
                <code>
                  {item.record.type} (TYPE{item.rr_type_code})
                </code>
              </DescriptionListDescription>
            </DescriptionListGroup>
            {rdataPairs.map((pair) => (
              <DescriptionListGroup key={pair.label}>
                <DescriptionListTerm>{pair.label}</DescriptionListTerm>
                <DescriptionListDescription>
                  <code>{pair.value}</code>
                </DescriptionListDescription>
              </DescriptionListGroup>
            ))}
            <DescriptionListGroup>
              <DescriptionListTerm>Record ID</DescriptionListTerm>
              <DescriptionListDescription>
                <code>{item.id}</code>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionListGroup>
              <DescriptionListTerm>Last Updated</DescriptionListTerm>
              <DescriptionListDescription>
                {formatUpdatedEpoch(item.updated_at_epoch)}
              </DescriptionListDescription>
            </DescriptionListGroup>
            {item.comment && (
              <DescriptionListGroup>
                <DescriptionListTerm>Audit Comment</DescriptionListTerm>
                <DescriptionListDescription>{item.comment}</DescriptionListDescription>
              </DescriptionListGroup>
            )}
          </DescriptionList>
        </GridItem>
        <GridItem md={5}>
          <DescriptionList isCompact>
            <DescriptionListGroup>
              <DescriptionListTerm>RFC 1035 Master Zone Line</DescriptionListTerm>
              <DescriptionListDescription>
                <ClipboardCopy isReadOnly hoverTip="Copy BIND line" clickTip="Copied">
                  {item.bind_preview}
                </ClipboardCopy>
              </DescriptionListDescription>
            </DescriptionListGroup>
          </DescriptionList>
        </GridItem>
      </Grid>
    </ExpandableRowContent>
  );
}
