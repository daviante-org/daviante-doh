import React from 'react';
import { Card, CardBody, CardHeader, CardTitle, CodeBlock, CodeBlockCode } from '@patternfly/react-core';
import type { LookupJsonPayloadCardProps } from '../types/lookup.types';

export function LookupJsonPayloadCard({
  result
}: LookupJsonPayloadCardProps): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>RFC 8484 Structured Diagnostic JSON Payload</CardTitle>
      </CardHeader>
      <CardBody>
        <CodeBlock>
          <CodeBlockCode id="dns-lookup-json-output">
            {JSON.stringify(result, null, 2)}
          </CodeBlockCode>
        </CodeBlock>
      </CardBody>
    </Card>
  );
}
