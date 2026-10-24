import React from 'react';
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Flex,
  FlexItem,
  Form,
  FormGroup,
  Grid,
  GridItem,
  Spinner,
  Switch,
  TextInput
} from '@patternfly/react-core';
import type { PolicyEnforcementCardProps } from '../types/policy.types';

export function PolicyEnforcementCard({
  settings,
  isReadOnly,
  isSavingSettings,
  onUpdateSettingsField,
  onSaveSettings
}: PolicyEnforcementCardProps): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Global Policy Enforcement Settings</CardTitle>
      </CardHeader>
      <CardBody>
        {settings === null ? (
          <Spinner size="md" aria-label="Loading policy settings" />
        ) : (
          <Form>
            <Grid hasGutter>
              <GridItem md={6}>
                <FormGroup label="Protective DNS Filtering" fieldId="policy-enabled-switch">
                  <Switch
                    id="policy-enabled-switch"
                    label="Protective DNS filtering enabled"
                    isChecked={settings.enabled}
                    isDisabled={isReadOnly}
                    onChange={(_event, checked) => { onUpdateSettingsField('enabled', checked); }}
                  />
                </FormGroup>
              </GridItem>
              <GridItem md={6}>
                <FormGroup
                  label="DNS Rebinding Protection (RFC 1918 / Loopback / Link-Local)"
                  fieldId="policy-rebinding-switch"
                >
                  <Switch
                    id="policy-rebinding-switch"
                    label="Block private IP responses from upstream resolvers"
                    isChecked={settings.block_private_rebinding}
                    isDisabled={isReadOnly}
                    onChange={(_event, checked) =>
                      { onUpdateSettingsField('block_private_rebinding', checked); }
                    }
                  />
                </FormGroup>
              </GridItem>
              <GridItem md={6}>
                <FormGroup label="Sinkhole IPv4 Address" fieldId="policy-sinkhole-v4">
                  <TextInput
                    id="policy-sinkhole-v4"
                    value={settings.sinkhole_ipv4}
                    maxLength={45}
                    isDisabled={isReadOnly}
                    onChange={(_event, value) => { onUpdateSettingsField('sinkhole_ipv4', value); }}
                  />
                </FormGroup>
              </GridItem>
              <GridItem md={6}>
                <FormGroup label="Sinkhole IPv6 Address" fieldId="policy-sinkhole-v6">
                  <TextInput
                    id="policy-sinkhole-v6"
                    value={settings.sinkhole_ipv6}
                    maxLength={45}
                    isDisabled={isReadOnly}
                    onChange={(_event, value) => { onUpdateSettingsField('sinkhole_ipv6', value); }}
                  />
                </FormGroup>
              </GridItem>
            </Grid>
            {!isReadOnly && (
              <Flex gap={{ default: 'gapSm' }}>
                <FlexItem>
                  <Button
                    variant="primary"
                    isLoading={isSavingSettings}
                    isDisabled={isSavingSettings}
                    onClick={() => {
                      void onSaveSettings();
                    }}
                  >
                    Save Policy Settings
                  </Button>
                </FlexItem>
              </Flex>
            )}
          </Form>
        )}
      </CardBody>
    </Card>
  );
}
