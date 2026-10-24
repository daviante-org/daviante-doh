import React, { useState } from 'react';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Checkbox,
  Content,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Divider,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
  Form,
  FormGroup,
  Grid,
  GridItem,
  Label,
  Stack,
  StackItem,
  TextInput
} from '@patternfly/react-core';
import {
  CheckCircleIcon,
  PencilAltIcon,
  ShieldAltIcon,
  TrashIcon
} from '@patternfly/react-icons';
import type { RuleId } from '../../../types';
import { formatUpdatedEpoch } from '../../../utils';
import type { DnsRuleView, PolicySettingsView } from '../types/policy.types';
import { renderPolicyActionLabel } from './PolicyRuleDirectoryCard';

export interface PolicyRuleDetailCardProps {
  readonly selectedRule: DnsRuleView | null;
  readonly settings: PolicySettingsView | null;
  readonly isReadOnly: boolean;
  readonly isSavingSettings: boolean;
  readonly onUpdateSettingsField: <K extends keyof PolicySettingsView>(
    field: K,
    value: PolicySettingsView[K]
  ) => void;
  readonly onSaveSettings: () => Promise<void>;
  readonly onDeleteRule: (ruleId: RuleId) => Promise<void>;
}

export function PolicyRuleDetailCard({
  selectedRule,
  settings,
  isReadOnly,
  isSavingSettings,
  onUpdateSettingsField,
  onSaveSettings,
  onDeleteRule
}: PolicyRuleDetailCardProps): React.JSX.Element {
  const [isEditingSettings, setIsEditingSettings] = useState(false);

  const handleSaveGlobalSettings = async (): Promise<void> => {
    await onSaveSettings();
    setIsEditingSettings(false);
  };

  return (
    <Card isFullHeight>
      {selectedRule ? (
        <>
          <CardHeader>
            <Flex
              direction={{ default: 'column' }}
              flexWrap={{ default: 'nowrap' }}
              spaceItems={{ default: 'spaceItemsXs' }}
            >
              <FlexItem>
                <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                  <FlexItem>
                    <CardTitle className="pf-v6-u-font-family-monospace">
                      {selectedRule.pattern}
                    </CardTitle>
                  </FlexItem>
                  <FlexItem>{renderPolicyActionLabel(selectedRule.action, false)}</FlexItem>
                  <FlexItem>
                    <Label
                      color={selectedRule.match_mode === 'Suffix' ? 'purple' : 'blue'}
                      icon={<ShieldAltIcon />}
                    >
                      {selectedRule.match_mode} match
                    </Label>
                  </FlexItem>
                </Flex>
              </FlexItem>

              <FlexItem>
                <Content component="p">
                  {selectedRule.comment || 'No operator comment provided'}
                </Content>
              </FlexItem>

              <FlexItem>
                <Content component="small">
                  Rule ID: <code>{selectedRule.id}</code> &bull; Last updated{' '}
                  {formatUpdatedEpoch(selectedRule.updated_at_epoch)}
                </Content>
              </FlexItem>
            </Flex>
          </CardHeader>

          <Divider />
        </>
      ) : null}

      <CardBody isFilled>
        <Stack hasGutter>
          {/* Section 1: Selected Policy Rule Inspector */}
          <StackItem>
            {selectedRule ? (
              <Card isCompact variant="secondary">
                <CardHeader>
                  <Flex
                    justifyContent={{ default: 'justifyContentSpaceBetween' }}
                    alignItems={{ default: 'alignItemsCenter' }}
                    gap={{ default: 'gapSm' }}
                  >
                    <FlexItem>
                      <strong>Selected Rule Enforcement Details</strong>
                    </FlexItem>
                    <FlexItem>
                      <Badge isRead={false}>{selectedRule.action}</Badge>
                    </FlexItem>
                  </Flex>
                </CardHeader>

                <Divider />

                <CardBody>
                  <Stack hasGutter>
                    <StackItem>
                      <DescriptionList
                        isCompact
                        columnModifier={{ default: '1Col', md: '3Col' }}
                      >
                        <DescriptionListGroup>
                          <DescriptionListTerm>Matched domain scope</DescriptionListTerm>
                          <DescriptionListDescription>
                            <code>
                              {selectedRule.match_mode === 'Suffix'
                                ? `${selectedRule.pattern} + all subdomains`
                                : `${selectedRule.pattern} (exact QNAME only)`}
                            </code>
                          </DescriptionListDescription>
                        </DescriptionListGroup>
                        <DescriptionListGroup>
                          <DescriptionListTerm>Resolver action</DescriptionListTerm>
                          <DescriptionListDescription>
                            {selectedRule.action === 'Allow'
                              ? 'Bypass threat filtering & resolve normally'
                              : selectedRule.action === 'BlockNxDomain'
                                ? 'Synthesize immediate RCODE 3 (NXDOMAIN)'
                                : `Rewrite A/AAAA to Sinkhole (${settings?.sinkhole_ipv4 ?? '0.0.0.0'} / ${settings?.sinkhole_ipv6 ?? '::'})`}
                          </DescriptionListDescription>
                        </DescriptionListGroup>
                        <DescriptionListGroup>
                          <DescriptionListTerm>Audit comment</DescriptionListTerm>
                          <DescriptionListDescription>
                            {selectedRule.comment || 'Not provided'}
                          </DescriptionListDescription>
                        </DescriptionListGroup>
                      </DescriptionList>
                    </StackItem>

                    {!isReadOnly && (
                      <StackItem>
                        <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                          <FlexItem>
                            <Button
                              variant="danger"
                              size="sm"
                              icon={<TrashIcon />}
                              onClick={() => {
                                void onDeleteRule(selectedRule.id);
                              }}
                            >
                              Delete rule
                            </Button>
                          </FlexItem>
                        </Flex>
                      </StackItem>
                    )}
                  </Stack>
                </CardBody>
              </Card>
            ) : (
              <EmptyState
                variant="sm"
                titleText="Select a policy rule"
                headingLevel="h3"
                icon={ShieldAltIcon}
              >
                <EmptyStateBody>
                  Choose a protective DNS rule from the directory on the left to inspect its
                  matching scope and enforcement action.
                </EmptyStateBody>
              </EmptyState>
            )}
          </StackItem>

          {/* Section 2: Global Policy Enforcement & Sinkhole Settings */}
          {settings !== null && (
            <StackItem>
              <Card isCompact variant="secondary">
                <CardHeader>
                  <Flex
                    justifyContent={{ default: 'justifyContentSpaceBetween' }}
                    alignItems={{ default: 'alignItemsCenter' }}
                    gap={{ default: 'gapSm' }}
                  >
                    <FlexItem>
                      <strong>
                        Global Policy Enforcement &amp; DNS Rebinding Protection
                      </strong>
                    </FlexItem>
                    {!isReadOnly && (
                      <FlexItem>
                        {isEditingSettings ? (
                          <Flex gap={{ default: 'gapSm' }} alignItems={{ default: 'alignItemsCenter' }}>
                            <FlexItem>
                              <Button
                                variant="primary"
                                size="sm"
                                isLoading={isSavingSettings}
                                isDisabled={isSavingSettings}
                                onClick={() => {
                                  void handleSaveGlobalSettings();
                                }}
                              >
                                Save changes
                              </Button>
                            </FlexItem>
                            <FlexItem>
                              <Button
                                variant="secondary"
                                size="sm"
                                isDisabled={isSavingSettings}
                                onClick={() => {
                                  setIsEditingSettings(false);
                                }}
                              >
                                Cancel
                              </Button>
                            </FlexItem>
                          </Flex>
                        ) : (
                          <Button
                            variant="secondary"
                            size="sm"
                            icon={<PencilAltIcon />}
                            onClick={() => {
                              setIsEditingSettings(true);
                            }}
                          >
                            Edit details
                          </Button>
                        )}
                      </FlexItem>
                    )}
                  </Flex>
                </CardHeader>

                <Divider />

                <CardBody>
                  <Form>
                    <Grid hasGutter>
                      <GridItem span={12} md={6}>
                        <FormGroup
                          label="Protective DNS policy engine"
                          fieldId="policy-enabled-checkbox"
                        >
                          <Checkbox
                            id="policy-enabled-checkbox"
                            label="Enable Protective DNS Policy Engine"
                            isChecked={settings.enabled}
                            isDisabled={!isEditingSettings || isReadOnly}
                            onChange={(_event, checked) => {
                              onUpdateSettingsField('enabled', checked);
                            }}
                          />
                        </FormGroup>
                      </GridItem>

                      <GridItem span={12} md={6}>
                        <FormGroup
                          label="RFC 1918 DNS rebinding defense"
                          fieldId="policy-rebinding-checkbox"
                        >
                          <Checkbox
                            id="policy-rebinding-checkbox"
                            label="Block Private/Loopback IP Responses from Public Upstreams"
                            isChecked={settings.block_private_rebinding}
                            isDisabled={!isEditingSettings || isReadOnly}
                            onChange={(_event, checked) => {
                              onUpdateSettingsField('block_private_rebinding', checked);
                            }}
                          />
                        </FormGroup>
                      </GridItem>

                      <GridItem span={12} md={6}>
                        <FormGroup
                          label="Sinkhole IPv4 target"
                          fieldId="sinkhole-ipv4-input"
                        >
                          <TextInput
                            id="sinkhole-ipv4-input"
                            value={settings.sinkhole_ipv4}
                            isDisabled={!isEditingSettings || isReadOnly}
                            maxLength={45}
                            onChange={(_event, val) => {
                              onUpdateSettingsField('sinkhole_ipv4', val);
                            }}
                          />
                        </FormGroup>
                      </GridItem>

                      <GridItem span={12} md={6}>
                        <FormGroup
                          label="Sinkhole IPv6 target"
                          fieldId="sinkhole-ipv6-input"
                        >
                          <TextInput
                            id="sinkhole-ipv6-input"
                            value={settings.sinkhole_ipv6}
                            isDisabled={!isEditingSettings || isReadOnly}
                            maxLength={45}
                            onChange={(_event, val) => {
                              onUpdateSettingsField('sinkhole_ipv6', val);
                            }}
                          />
                        </FormGroup>
                      </GridItem>
                    </Grid>
                  </Form>
                </CardBody>
              </Card>
            </StackItem>
          )}

          {/* Section 3: Evaluation Precedence Matrix */}
          <StackItem>
            <Card isCompact variant="secondary">
              <CardHeader>
                <Flex
                  justifyContent={{ default: 'justifyContentSpaceBetween' }}
                  alignItems={{ default: 'alignItemsCenter' }}
                  gap={{ default: 'gapSm' }}
                >
                  <FlexItem>
                    <strong>Resolver Policy Evaluation Precedence</strong>
                  </FlexItem>
                  <FlexItem>
                    <Badge isRead>Deterministic Order</Badge>
                  </FlexItem>
                </Flex>
              </CardHeader>

              <Divider />

              <CardBody>
                <Flex gap={{ default: 'gapXs' }} alignItems={{ default: 'alignItemsCenter' }}>
                  <FlexItem>
                    <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                      1. Exact Allow
                    </Label>
                  </FlexItem>
                  <FlexItem>
                    <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                      2. Exact Block / Sinkhole
                    </Label>
                  </FlexItem>
                  <FlexItem>
                    <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                      3. Longest Suffix Match
                    </Label>
                  </FlexItem>
                  <FlexItem>
                    <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                      4. Local Authoritative Zone
                    </Label>
                  </FlexItem>
                  <FlexItem>
                    <Label color="blue" isCompact icon={<CheckCircleIcon />}>
                      5. Upstream DoH/DoT + Rebinding Check
                    </Label>
                  </FlexItem>
                </Flex>
              </CardBody>
            </Card>
          </StackItem>
        </Stack>
      </CardBody>
    </Card>
  );
}
