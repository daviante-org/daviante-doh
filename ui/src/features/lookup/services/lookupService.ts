import { httpClient } from '../../../services';
import type { DnsRecordType } from '../../../types';
import { DnsLookupResponseSchema, type DnsLookupResponse } from '../types/lookup.types';

export const lookupService = {
  async runDnsLookup(payload: {
    domain: string;
    rr_type: DnsRecordType;
    dnssec_do: boolean;
    checking_disabled: boolean;
  }): Promise<DnsLookupResponse> {
    return httpClient.request(
      '/api/v1/dns/lookup',
      {
        method: 'POST',
        body: JSON.stringify({
          name: payload.domain,
          record_type: payload.rr_type,
          do_bit: payload.dnssec_do
        })
      },
      DnsLookupResponseSchema
    );
  }
};
