import React, { useEffect, useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import {
  Alert,
  Button,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Stack,
  StackItem,
  TextInput
} from '@patternfly/react-core';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import {
  AddRuleFormSchema,
  type AddPolicyRuleModalProps,
  type AddRuleFormValues,
  type PolicyAction,
  type PolicyMatchMode
} from '../types/policy.types';

export function AddPolicyRuleModal({
  isOpen,
  onClose,
  onSubmitRule
}: AddPolicyRuleModalProps): React.JSX.Element {
  const [modalError, setModalError] = useState<string | null>(null);
  const [isCreatingRule, setIsCreatingRule] = useState(false);

  const {
    control,
    handleSubmit,
    reset,
    formState: { errors }
  } = useForm<AddRuleFormValues>({
    resolver: zodResolver(AddRuleFormSchema),
    defaultValues: {
      pattern: '',
      match_mode: 'Suffix',
      action: 'BlockNxDomain',
      comment: ''
    }
  });

  useEffect(() => {
    if (isOpen) {
      setModalError(null);
      reset({
        pattern: '',
        match_mode: 'Suffix',
        action: 'BlockNxDomain',
        comment: ''
      });
    }
  }, [isOpen, reset]);

  const onFormSubmit = async (values: AddRuleFormValues): Promise<void> => {
    setModalError(null);
    setIsCreatingRule(true);
    try {
      await onSubmitRule(values);
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setModalError(err.userMessage);
      } else {
        setModalError(mapErrorCodeToStaticMessage('UNKNOWN_ERROR'));
      }
    } finally {
      setIsCreatingRule(false);
    }
  };

  return (
    <Modal
      variant={ModalVariant.medium}
      isOpen={isOpen}
      onClose={onClose}
      aria-label="Add Protective DNS Policy Rule"
    >
      <ModalHeader title="Add Protective DNS Policy Rule" />
      <ModalBody>
        <Stack hasGutter>
          {modalError !== null && (
            <StackItem>
              <Alert variant="danger" isInline title={modalError} />
            </StackItem>
          )}
          <StackItem>
            <Form id="add-policy-rule-form" onSubmit={(e) => void handleSubmit(onFormSubmit)(e)}>
              <FormGroup label="Domain Pattern" isRequired fieldId="rule-pattern">
                <Controller
                  name="pattern"
                  control={control}
                  render={({ field }) => (
                    <TextInput
                      id="rule-pattern"
                      value={field.value}
                      onChange={(_e, val) => { field.onChange(val); }}
                      maxLength={253}
                      placeholder="malware.example.net"
                      validated={errors.pattern ? 'error' : 'default'}
                    />
                  )}
                />
                <FormHelperText>
                  <HelperText>
                    <HelperTextItem variant={errors.pattern ? 'error' : 'default'}>
                      {errors.pattern?.message ??
                        'Suffix mode matches the domain and all of its subdomains.'}
                    </HelperTextItem>
                  </HelperText>
                </FormHelperText>
              </FormGroup>

              <FormGroup label="Match Mode" isRequired fieldId="rule-match-mode">
                <Controller
                  name="match_mode"
                  control={control}
                  render={({ field }) => (
                    <FormSelect
                      id="rule-match-mode"
                      value={field.value}
                      onChange={(_e, val) => { field.onChange(val as PolicyMatchMode); }}
                    >
                      <FormSelectOption
                        value="Suffix"
                        label="Suffix Match (domain + all subdomains)"
                      />
                      <FormSelectOption value="Exact" label="Exact Hostname Match Only" />
                    </FormSelect>
                  )}
                />
              </FormGroup>

              <FormGroup label="Enforcement Action" isRequired fieldId="rule-action">
                <Controller
                  name="action"
                  control={control}
                  render={({ field }) => (
                    <FormSelect
                      id="rule-action"
                      value={field.value}
                      onChange={(_e, val) => { field.onChange(val as PolicyAction); }}
                    >
                      <FormSelectOption
                        value="BlockNxDomain"
                        label="Block with NXDOMAIN (RCODE 3)"
                      />
                      <FormSelectOption
                        value="Sinkhole"
                        label="Sinkhole (Respond with Sinkhole IPv4/IPv6)"
                      />
                      <FormSelectOption
                        value="Allow"
                        label="Allowlist (Override broader Suffix blocks)"
                      />
                    </FormSelect>
                  )}
                />
              </FormGroup>

              <FormGroup label="Audit Comment" fieldId="rule-comment">
                <Controller
                  name="comment"
                  control={control}
                  render={({ field }) => (
                    <TextInput
                      id="rule-comment"
                      value={field.value}
                      onChange={(_e, val) => { field.onChange(val); }}
                      maxLength={256}
                      placeholder="Optional ticket ID or threat intelligence source"
                    />
                  )}
                />
              </FormGroup>
            </Form>
          </StackItem>
        </Stack>
      </ModalBody>
      <ModalFooter>
        <Button
          variant="primary"
          type="submit"
          form="add-policy-rule-form"
          isLoading={isCreatingRule}
          isDisabled={isCreatingRule}
        >
          Create Rule
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={isCreatingRule}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
