import React from 'react';
import {
  Button,
  FormSelect,
  FormSelectOption,
  Pagination,
  SearchInput,
  ToggleGroup,
  ToggleGroupItem,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem
} from '@patternfly/react-core';
import {
  DNS_RECORD_TYPES,
  PER_PAGE_OPTIONS,
  type RecordCategoryFilter
} from '../../../constants';

export interface RecordsToolbarProps {
  readonly searchInput: string;
  readonly filterRecordType: string;
  readonly categoryFilter: RecordCategoryFilter;
  readonly filterEnabled: 'all' | 'enabled' | 'disabled';
  readonly selectedCount: number;
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
  readonly isReadOnly: boolean;
  readonly onSearchChange: (val: string) => void;
  readonly onRecordTypeChange: (val: string) => void;
  readonly onCategoryChange: (cat: RecordCategoryFilter) => void;
  readonly onEnabledFilterChange: (val: 'all' | 'enabled' | 'disabled') => void;
  readonly onBulkDelete: () => Promise<void>;
  readonly onPageChange: (page: number) => void;
  readonly onPerPageChange: (perPage: number) => void;
}

export function RecordsToolbar({
  searchInput,
  filterRecordType,
  categoryFilter,
  filterEnabled,
  selectedCount,
  total,
  page,
  perPage,
  isReadOnly,
  onSearchChange,
  onRecordTypeChange,
  onCategoryChange,
  onEnabledFilterChange,
  onBulkDelete,
  onPageChange,
  onPerPageChange
}: RecordsToolbarProps): React.JSX.Element {
  return (
    <Toolbar id="dns-records-toolbar" clearAllFilters={() => { onSearchChange(''); }}>
      <ToolbarContent>
        <ToolbarGroup>
          <ToolbarItem>
            <SearchInput
              aria-label="Filter DNS records by domain, value, or comment"
              placeholder="Search owner, IP/target, or comment..."
              value={searchInput}
              onChange={(_event, val) => {
                onSearchChange(val);
                onPageChange(1);
              }}
              onClear={() => {
                onSearchChange('');
                onPageChange(1);
              }}
            />
          </ToolbarItem>
          <ToolbarItem>
            <FormSelect
              id="dns-records-type-filter"
              aria-label="Filter by exact RR type"
              value={filterRecordType}
              onChange={(_e, val) => { onRecordTypeChange(val); }}
            >
              <FormSelectOption value="" label="All 29 RR Types" />
              {DNS_RECORD_TYPES.map((rrType) => (
                <FormSelectOption key={rrType} value={rrType} label={rrType} />
              ))}
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem>
            <ToggleGroup aria-label="Filter records by DNS category" isCompact>
              <ToggleGroupItem
                text="All"
                buttonId="cat-all"
                isSelected={categoryFilter === 'ALL'}
                onChange={() => { onCategoryChange('ALL'); }}
              />
              <ToggleGroupItem
                text="Address & Alias"
                buttonId="cat-addr"
                isSelected={categoryFilter === 'ADDRESS'}
                onChange={() => { onCategoryChange('ADDRESS'); }}
              />
              <ToggleGroupItem
                text="Mail & TXT"
                buttonId="cat-mail"
                isSelected={categoryFilter === 'MAIL_TEXT'}
                onChange={() => { onCategoryChange('MAIL_TEXT'); }}
              />
              <ToggleGroupItem
                text="Services"
                buttonId="cat-svc"
                isSelected={categoryFilter === 'SERVICE'}
                onChange={() => { onCategoryChange('SERVICE'); }}
              />
              <ToggleGroupItem
                text="Security & DNSSEC"
                buttonId="cat-sec"
                isSelected={categoryFilter === 'SECURITY'}
                onChange={() => { onCategoryChange('SECURITY'); }}
              />
              <ToggleGroupItem
                text="Infra"
                buttonId="cat-infra"
                isSelected={categoryFilter === 'INFRA'}
                onChange={() => { onCategoryChange('INFRA'); }}
              />
            </ToggleGroup>
          </ToolbarItem>
          <ToolbarItem>
            <FormSelect
              id="dns-records-status-filter"
              aria-label="Filter by status"
              value={filterEnabled}
              onChange={(_e, val) => {
                onEnabledFilterChange(val as 'all' | 'enabled' | 'disabled');
                onPageChange(1);
              }}
            >
              <FormSelectOption value="all" label="All Statuses" />
              <FormSelectOption value="enabled" label="Enabled Only" />
              <FormSelectOption value="disabled" label="Disabled Only" />
            </FormSelect>
          </ToolbarItem>
        </ToolbarGroup>

        {!isReadOnly && selectedCount > 0 && (
          <ToolbarGroup>
            <ToolbarItem>
              <Button variant="danger" size="sm" onClick={() => void onBulkDelete()}>
                Delete Selected ({selectedCount})
              </Button>
            </ToolbarItem>
          </ToolbarGroup>
        )}

        <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
          <Pagination
            itemCount={total}
            perPage={perPage}
            page={page}
            perPageOptions={[...PER_PAGE_OPTIONS]}
            onSetPage={(_event, nextPage) => { onPageChange(nextPage); }}
            onPerPageSelect={(_event, nextPerPage) => {
              onPerPageChange(Math.min(nextPerPage, 100));
              onPageChange(1);
            }}
            isCompact
          />
        </ToolbarItem>
      </ToolbarContent>
    </Toolbar>
  );
}
