import React from 'react';
import { Controller } from 'react-hook-form';
import {
  Alert,
  Button,
  CodeBlock,
  CodeBlockCode,
  Flex,
  FlexItem,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  FormSelectOptionGroup,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Stack,
  StackItem,
  Switch,
  TextInput
} from '@patternfly/react-core';
import {
  type DnsRecordType,
  RECORD_TYPE_GROUPS,
  TTL_PRESETS
} from '../../../constants';
import { parseIntClamped } from '../../../utils';
import { useRecordFormModal } from '../hooks/useRecordFormModal';
import type { CloudflareRecordModalProps } from '../types/dnsRecords.types';
import { RecordTypeSpecificFields } from './RecordTypeSpecificFields';

export function CloudflareRecordModal({
  isOpen,
  editRecord,
  isCloneMode = false,
  activeZone,
  existingRecords,
  onClose,
  onSubmitRecord
}: CloudflareRecordModalProps): React.JSX.Element {
  const {
    form,
    submitError,
    isSubmitting,
    serverPreview,
    watchedRecord,
    resolvedDomainPreview,
    liveBindLine,
    handleRecordTypeChange,
    updateRecordField,
    onFormSubmit
  } = useRecordFormModal({
    isOpen,
    editRecord,
    isCloneMode,
    activeZone,
    existingRecords,
    onClose,
    onSubmitRecord
  });

  const {
    control,
    handleSubmit,
    setValue,
    formState: { errors }
  } = form;

  const rdataErrorMessage =
    errors.record && typeof errors.record === 'object' && 'message' in errors.record
      ? (errors.record.message ?? null)
      : null;

  const modalTitle =
    editRecord !== null
      ? isCloneMode
        ? `Clone Local DNS Record (${editRecord.record.type} — ${editRecord.domain})`
        : `Edit Local DNS Record (${editRecord.record.type} — ${editRecord.domain})`
      : activeZone !== null
        ? `Add Record to Zone: ${activeZone.name}`
        : 'Add Local DNS Record (All 29 IANA RR Types)';

  return (
    <Modal
      variant={ModalVariant.large}
      isOpen={isOpen}
      onClose={onClose}
      aria-label={modalTitle}
    >
      <ModalHeader
        title={modalTitle}
        description="Configure DNS resource record parameters with real-time RFC 1035 wire-format and CNAME conflict validation."
      />
      <ModalBody>
        <Stack hasGutter>
          {submitError !== null && (
            <StackItem>
              <Alert variant="danger" isInline title={submitError} />
            </StackItem>
          )}

          {rdataErrorMessage !== null && (
            <StackItem>
              <Alert variant="warning" isInline title={rdataErrorMessage} />
            </StackItem>
          )}

          <StackItem>
            <Form id="cloudflare-record-form" onSubmit={(e) => void handleSubmit(onFormSubmit)(e)}>
              <Grid hasGutter>
                <GridItem md={4}>
                  <FormGroup label="Record Type" isRequired fieldId="cf-record-type">
                    <FormSelect
                      id="cf-record-type"
                      value={watchedRecord.type}
                      onChange={(_e, val) => { handleRecordTypeChange(val as DnsRecordType); }}
                      aria-label="DNS Record Type"
                    >
                      {RECORD_TYPE_GROUPS.map((group) => (
                        <FormSelectOptionGroup key={group.label} label={group.label}>
                          {group.types.map((opt) => (
                            <FormSelectOption
                              key={opt.value}
                              value={opt.value}
                              label={opt.label}
                            />
                          ))}
                        </FormSelectOptionGroup>
                      ))}
                    </FormSelect>
                  </FormGroup>
                </GridItem>

                <GridItem md={5}>
                  <FormGroup
                    label={
                      watchedRecord.type === 'PTR'
                        ? 'IP Address or .arpa Owner Name'
                        : activeZone !== null
                          ? `Owner Name in Zone (${activeZone.name})`
                          : 'Owner / Domain Name (FQDN)'
                    }
                    isRequired
                    fieldId="cf-domain"
                  >
                    <Controller
                      name="domain"
                      control={control}
                      render={({ field }) => (
                        <TextInput
                          id="cf-domain"
                          value={field.value}
                          onChange={(_e, val) => { field.onChange(val); }}
                          maxLength={253}
                          placeholder={
                            watchedRecord.type === 'PTR'
                              ? '10.0.0.10 or 10.0.0.10.in-addr.arpa'
                              : activeZone !== null
                                ? '@ or api or *.svc'
                                : 'api.internal.corp'
                          }
                          validated={errors.domain ? 'error' : 'default'}
                        />
                      )}
                    />
                    <FormHelperText>
                      <HelperText>
                        <HelperTextItem variant={errors.domain ? 'error' : 'default'}>
                          {errors.domain?.message ??
                            (watchedRecord.type === 'PTR'
                              ? 'Raw IPv4/IPv6 addresses are automatically converted to canonical .in-addr.arpa / .ip6.arpa.'
                              : activeZone !== null
                                ? `Resolves to: ${resolvedDomainPreview}`
                                : 'Supports wildcard prefix (*.domain) and underscore service labels (_443._tcp).')}
                        </HelperTextItem>
                      </HelperText>
                    </FormHelperText>
                  </FormGroup>
                </GridItem>

                <GridItem md={3}>
                  <FormGroup label="TTL (Seconds)" isRequired fieldId="cf-ttl">
                    <Controller
                      name="ttl"
                      control={control}
                      render={({ field }) => (
                        <TextInput
                          id="cf-ttl"
                          type="number"
                          value={field.value}
                          onChange={(_e, val) =>
                            { field.onChange(parseIntClamped(val, 300, 1, 604800)); }
                          }
                          validated={errors.ttl ? 'error' : 'default'}
                        />
                      )}
                    />
                    <FormHelperText>
                      <HelperText>
                        <HelperTextItem>
                          <Flex gap={{ default: 'gapXs' }}>
                            {TTL_PRESETS.slice(0, 4).map((preset) => (
                              <FlexItem key={preset.value}>
                                <Button
                                  variant="link"
                                  isInline
                                  size="sm"
                                  onClick={() =>
                                    { setValue('ttl', preset.value, { shouldValidate: true }); }
                                  }
                                >
                                  {preset.value}s
                                </Button>
                              </FlexItem>
                            ))}
                          </Flex>
                        </HelperTextItem>
                      </HelperText>
                    </FormHelperText>
                  </FormGroup>
                </GridItem>
              </Grid>

              <RecordTypeSpecificFields
                record={watchedRecord}
                onUpdateRecord={updateRecordField}
              />

              <Grid hasGutter>
                <GridItem md={8}>
                  <FormGroup label="Audit Comment / Notes" fieldId="cf-comment">
                    <Controller
                      name="comment"
                      control={control}
                      render={({ field }) => (
                        <TextInput
                          id="cf-comment"
                          value={field.value}
                          onChange={(_e, val) => { field.onChange(val); }}
                          maxLength={256}
                          placeholder="Optional ticket ID, service owner, or RFC note"
                        />
                      )}
                    />
                  </FormGroup>
                </GridItem>
                <GridItem md={4}>
                  <FormGroup label="Record Status" fieldId="cf-enabled">
                    <Controller
                      name="enabled"
                      control={control}
                      render={({ field }) => (
                        <Switch
                          id="cf-enabled"
                          label="Record active and served by DoH"
                          isChecked={field.value}
                          onChange={(_e, checked) => { field.onChange(checked); }}
                        />
                      )}
                    />
                  </FormGroup>
                </GridItem>
              </Grid>
            </Form>
          </StackItem>

          <StackItem>
            <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
              <FlexItem>
                <strong>Live RFC 1035 / BIND Zone File Preview</strong>
              </FlexItem>
              {serverPreview !== null && (
                <>
                  <FlexItem>
                    <Label isCompact color="blue">
                      TYPE{serverPreview.rr_type_code}
                    </Label>
                  </FlexItem>
                  <FlexItem>
                    <Label isCompact color="green">
                      Wire RDATA: {serverPreview.wire_size_bytes} B
                    </Label>
                  </FlexItem>
                  {serverPreview.auto_ptr_preview !== null && (
                    <FlexItem>
                      <Label isCompact color="purple">
                        Auto-PTR: {serverPreview.auto_ptr_preview}
                      </Label>
                    </FlexItem>
                  )}
                </>
              )}
            </Flex>
            <CodeBlock>
              <CodeBlockCode id="live-bind-preview-code">
                {serverPreview?.bind_line ?? liveBindLine}
              </CodeBlockCode>
            </CodeBlock>
          </StackItem>
        </Stack>
      </ModalBody>
      <ModalFooter>
        <Button
          variant="primary"
          type="submit"
          form="cloudflare-record-form"
          isLoading={isSubmitting}
          isDisabled={isSubmitting}
        >
          {editRecord !== null && !isCloneMode
            ? 'Save Record Changes'
            : isCloneMode
              ? 'Create Cloned Record'
              : 'Create Record'}
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={isSubmitting}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
