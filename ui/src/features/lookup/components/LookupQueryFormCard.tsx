import React from 'react';
import { Controller, type UseFormReturn } from 'react-hook-form';
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Checkbox,
  Flex,
  FlexItem,
  Form,
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
import { DNS_RECORD_TYPES, type DnsRecordType } from '../../../constants';
import type { DnsLookupFormValues } from '../types/lookup.types';

export interface LookupQueryFormCardProps {
  readonly form: UseFormReturn<DnsLookupFormValues>;
  readonly isRunning: boolean;
  readonly onSubmit: (values: DnsLookupFormValues) => Promise<void>;
}

export function LookupQueryFormCard({
  form,
  isRunning,
  onSubmit
}: LookupQueryFormCardProps): React.JSX.Element {
  const {
    control,
    handleSubmit,
    formState: { errors }
  } = form;

  return (
    <Card>
      <CardHeader>
        <CardTitle>DNS Query Parameters</CardTitle>
      </CardHeader>
      <CardBody>
        <Form id="dns-lookup-form" onSubmit={(e) => void handleSubmit(onSubmit)(e)}>
          <Grid hasGutter>
            <GridItem md={5}>
              <FormGroup label="Query Domain / IP (for PTR)" isRequired fieldId="lookup-domain">
                <Controller
                  name="domain"
                  control={control}
                  render={({ field }) => (
                    <TextInput
                      id="lookup-domain"
                      value={field.value}
                      onChange={(_e, val) => { field.onChange(val); }}
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
                        'Enter an FQDN or IPv4/IPv6 address (auto-converted to .arpa when RR type is PTR).'}
                    </HelperTextItem>
                  </HelperText>
                </FormHelperText>
              </FormGroup>
            </GridItem>

            <GridItem md={3}>
              <FormGroup label="Query RR Type" isRequired fieldId="lookup-rr-type">
                <Controller
                  name="rr_type"
                  control={control}
                  render={({ field }) => (
                    <FormSelect
                      id="lookup-rr-type"
                      value={field.value}
                      onChange={(_e, val) => { field.onChange(val as DnsRecordType); }}
                    >
                      {DNS_RECORD_TYPES.map((rrType) => (
                        <FormSelectOption key={rrType} value={rrType} label={rrType} />
                      ))}
                    </FormSelect>
                  )}
                />
              </FormGroup>
            </GridItem>

            <GridItem md={4}>
              <FormGroup label="DNSSEC & Validation Flags" fieldId="lookup-flags">
                <Flex gap={{ default: 'gapMd' }}>
                  <FlexItem>
                    <Controller
                      name="dnssec_do"
                      control={control}
                      render={({ field }) => (
                        <Checkbox
                          id="lookup-dnssec-do"
                          label="Request DNSSEC OK (DO=1)"
                          isChecked={field.value}
                          onChange={(_e, checked) => { field.onChange(checked); }}
                        />
                      )}
                    />
                  </FlexItem>
                  <FlexItem>
                    <Controller
                      name="checking_disabled"
                      control={control}
                      render={({ field }) => (
                        <Checkbox
                          id="lookup-cd"
                          label="Checking Disabled (CD=1)"
                          isChecked={field.value}
                          onChange={(_e, checked) => { field.onChange(checked); }}
                        />
                      )}
                    />
                  </FlexItem>
                </Flex>
              </FormGroup>
            </GridItem>
          </Grid>

          <Flex gap={{ default: 'gapSm' }}>
            <FlexItem>
              <Button
                variant="primary"
                type="submit"
                isLoading={isRunning}
                isDisabled={isRunning}
              >
                Execute DNS Lookup
              </Button>
            </FlexItem>
          </Flex>
        </Form>
      </CardBody>
    </Card>
  );
}
