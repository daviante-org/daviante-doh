import React from 'react';
import { Controller, type UseFormReturn } from 'react-hook-form';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Checkbox,
  Content,
  DataList,
  DataListCell,
  DataListItem,
  DataListItemCells,
  DataListItemRow,
  Divider,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Label,
  Stack,
  StackItem,
  TextInput
} from '@patternfly/react-core';
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  SearchIcon,
  ShieldAltIcon
} from '@patternfly/react-icons';
import { DNS_RECORD_TYPES, type DnsRecordType } from '../../../constants';
import type { LookupHistoryEntry } from '../hooks/useDnsLookup';
import type { DnsLookupFormValues } from '../types/lookup.types';

export interface LookupQueryDirectoryCardProps {
  readonly form: UseFormReturn<DnsLookupFormValues>;
  readonly isRunning: boolean;
  readonly history: readonly LookupHistoryEntry[];
  readonly selectedEntry: LookupHistoryEntry | null;
  readonly onSelectHistoryId: (id: string) => void;
  readonly onSubmit: (values: DnsLookupFormValues) => Promise<void>;
}

export function LookupQueryDirectoryCard({
  form,
  isRunning,
  history,
  selectedEntry,
  onSelectHistoryId,
  onSubmit
}: LookupQueryDirectoryCardProps): React.JSX.Element {
  const {
    control,
    handleSubmit,
    formState: { errors }
  } = form;

  return (
    <Card isFullHeight>
      <CardHeader>
        <Flex
          justifyContent={{ default: 'justifyContentSpaceBetween' }}
          alignItems={{ default: 'alignItemsCenter' }}
          gap={{ default: 'gapSm' }}
        >
          <FlexItem>
            <CardTitle>DNS Query Parameters</CardTitle>
          </FlexItem>
          <FlexItem>
            <Badge isRead={history.length === 0}>{history.length} recent</Badge>
          </FlexItem>
        </Flex>
      </CardHeader>

      <Divider />

      <CardBody isFilled>
        <Stack hasGutter>
          <StackItem>
            <Form id="dns-lookup-form" onSubmit={(e) => void handleSubmit(onSubmit)(e)}>
              <FormGroup
                label="Query Domain / IP (for PTR)"
                isRequired
                fieldId="lookup-domain"
              >
                <Controller
                  name="domain"
                  control={control}
                  render={({ field }) => (
                    <TextInput
                      id="lookup-domain"
                      value={field.value}
                      onChange={(_e, val) => {
                        field.onChange(val);
                      }}
                      maxLength={253}
                      placeholder="example.com"
                      validated={errors.domain ? 'error' : 'default'}
                    />
                  )}
                />
                <FormHelperText>
                  <HelperText>
                    <HelperTextItem variant={errors.domain ? 'error' : 'default'}>
                      {errors.domain?.message ??
                        'Enter an FQDN or IPv4/IPv6 address (auto-converted to .arpa for PTR).'}
                    </HelperTextItem>
                  </HelperText>
                </FormHelperText>
              </FormGroup>

              <FormGroup label="Query RR Type" isRequired fieldId="lookup-rr-type">
                <Controller
                  name="rr_type"
                  control={control}
                  render={({ field }) => (
                    <FormSelect
                      id="lookup-rr-type"
                      value={field.value}
                      onChange={(_e, val) => {
                        field.onChange(val as DnsRecordType);
                      }}
                    >
                      {DNS_RECORD_TYPES.map((rrType) => (
                        <FormSelectOption key={rrType} value={rrType} label={rrType} />
                      ))}
                    </FormSelect>
                  )}
                />
              </FormGroup>

              <FormGroup label="DNSSEC & Validation Flags" fieldId="lookup-flags">
                <Stack>
                  <StackItem>
                    <Controller
                      name="dnssec_do"
                      control={control}
                      render={({ field }) => (
                        <Checkbox
                          id="lookup-dnssec-do"
                          label="Request DNSSEC OK (DO=1)"
                          isChecked={field.value}
                          onChange={(_e, checked) => {
                            field.onChange(checked);
                          }}
                        />
                      )}
                    />
                  </StackItem>
                  <StackItem>
                    <Controller
                      name="checking_disabled"
                      control={control}
                      render={({ field }) => (
                        <Checkbox
                          id="lookup-cd"
                          label="Checking Disabled (CD=1)"
                          isChecked={field.value}
                          onChange={(_e, checked) => {
                            field.onChange(checked);
                          }}
                        />
                      )}
                    />
                  </StackItem>
                </Stack>
              </FormGroup>

              <Button
                variant="primary"
                type="submit"
                icon={<SearchIcon />}
                isLoading={isRunning}
                isDisabled={isRunning}
                isBlock
              >
                Execute DNS Lookup
              </Button>
            </Form>
          </StackItem>

          <StackItem>
            <Divider />
          </StackItem>

          <StackItem>
            <Flex
              justifyContent={{ default: 'justifyContentSpaceBetween' }}
              alignItems={{ default: 'alignItemsCenter' }}
            >
              <FlexItem>
                <strong>Recent Session Queries</strong>
              </FlexItem>
              <FlexItem>
                <Badge isRead>{history.length}</Badge>
              </FlexItem>
            </Flex>
          </StackItem>

          <StackItem>
            {history.length === 0 ? (
              <EmptyState
                variant="sm"
                titleText="No lookups executed yet"
                headingLevel="h3"
                icon={SearchIcon}
              >
                <EmptyStateBody>
                  Execute a diagnostic DNS query above to inspect resolution timing, answer
                  sections, and RFC 8484 wire payloads.
                </EmptyStateBody>
              </EmptyState>
            ) : (
              <DataList
                aria-label="Recent diagnostic DNS queries"
                isCompact
                selectedDataListItemId={selectedEntry?.id ?? ''}
                onSelectDataListItem={(_event, id) => {
                  onSelectHistoryId(id);
                }}
              >
                {history.map((entry) => {
                  const res = entry.response;
                  const rcodeColor =
                    res.response_code === 'NoError'
                      ? 'green'
                      : res.response_code === 'NXDomain'
                        ? 'orange'
                        : 'red';

                  return (
                    <DataListItem
                      key={entry.id}
                      id={entry.id}
                      aria-labelledby={`lookup-history-item-${entry.id}`}
                    >
                      <DataListItemRow>
                        <DataListItemCells
                          dataListCells={[
                            <DataListCell key="primary" isFilled>
                              <Flex
                                direction={{ default: 'column' }}
                                flexWrap={{ default: 'nowrap' }}
                                spaceItems={{ default: 'spaceItemsXs' }}
                              >
                                <FlexItem>
                                  <Flex
                                    justifyContent={{
                                      default: 'justifyContentSpaceBetween'
                                    }}
                                    alignItems={{ default: 'alignItemsCenter' }}
                                    gap={{ default: 'gapSm' }}
                                  >
                                    <FlexItem>
                                      <span id={`lookup-history-item-${entry.id}`}>
                                        <strong className="pf-v6-u-font-family-monospace">
                                          {res.question_name}
                                        </strong>
                                      </span>
                                    </FlexItem>
                                    <FlexItem>
                                      <Label
                                        color={rcodeColor}
                                        isCompact
                                        icon={
                                          res.response_code === 'NoError' ? (
                                            <CheckCircleIcon />
                                          ) : (
                                            <ExclamationTriangleIcon />
                                          )
                                        }
                                      >
                                        {res.response_code}
                                      </Label>
                                    </FlexItem>
                                  </Flex>
                                </FlexItem>

                                <FlexItem>
                                  <Content component="small">
                                    Source: {res.resolution_source} &bull;{' '}
                                    {res.latency_ms.toFixed(2)} ms &bull; {entry.executedAt}
                                  </Content>
                                </FlexItem>

                                <FlexItem>
                                  <Flex
                                    gap={{ default: 'gapSm' }}
                                    alignItems={{ default: 'alignItemsCenter' }}
                                  >
                                    <FlexItem>
                                      <Label
                                        color="blue"
                                        isCompact
                                        icon={<ShieldAltIcon />}
                                      >
                                        {res.question_type}
                                      </Label>
                                    </FlexItem>
                                    <FlexItem>
                                      <Label color="grey" isCompact variant="outline">
                                        {String(res.answers.length)} answer(s)
                                      </Label>
                                    </FlexItem>
                                  </Flex>
                                </FlexItem>
                              </Flex>
                            </DataListCell>
                          ]}
                        />
                      </DataListItemRow>
                    </DataListItem>
                  );
                })}
              </DataList>
            )}
          </StackItem>
        </Stack>
      </CardBody>
    </Card>
  );
}
