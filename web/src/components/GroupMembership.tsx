import { useState, useEffect, useRef, useCallback } from 'react';
import { Search } from 'lucide-react';
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from '@tanstack/react-table';
import type { User, Group, UserGroupStatus } from '../types';
import api from '../services/api';
import { useNotification } from '../contexts/NotificationContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

interface GroupMembershipProps {
  user: User;
  onUpdate?: () => void;
}

export function GroupMembership({ user, onUpdate }: GroupMembershipProps) {
  const [groups, setGroups] = useState<UserGroupStatus[]>([]);
  const [allGroups, setAllGroups] = useState<Group[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Group[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [pendingChanges, setPendingChanges] = useState<Map<string, 'add' | 'remove'>>(new Map());
  const { showNotification } = useNotification();
  const searchRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const extractCNFromDN = (dn: string): string => {
    const match = dn.match(/^CN=([^,]+)/i);
    return match ? match[1] : dn;
  };

  const loadAllGroups = useCallback(async () => {
    try {
      const response = await api.getAllGroups();
      if (response.success && response.groups) {
        setAllGroups(response.groups);
      }
    } catch {
      console.error('Failed to load groups');
    }
  }, []);

  const loadUserGroups = useCallback(() => {
    if (!user.memberOf) {
      setGroups([]);
      return;
    }

    const userGroups: UserGroupStatus[] = user.memberOf.map((groupDN) => {
      const groupName = extractCNFromDN(groupDN);
      const foundGroup = allGroups.find(
        (g) => g.cn === groupName || g.distinguishedName === groupDN
      );

      return {
        group: foundGroup || {
          dn: groupDN,
          cn: groupName,
          sAMAccountName: groupName,
          description: '',
        },
        isMember: true,
        membershipType: 'direct',
      };
    });

    setGroups(userGroups.sort((a, b) => a.group.cn.localeCompare(b.group.cn)));
  }, [user.memberOf, allGroups]);

  useEffect(() => {
    loadAllGroups();
  }, [loadAllGroups]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(event.target as Node)) {
        setIsSearchOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (allGroups.length > 0) {
      loadUserGroups();
    }
  }, [allGroups, user.memberOf, loadUserGroups]);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    if (searchQuery.length < 2) {
      setSearchResults([]);
      return;
    }

    debounceRef.current = setTimeout(async () => {
      setIsSearching(true);
      try {
        const response = await api.searchGroups(searchQuery);
        if (response.success && response.groups) {
          const existingDNs = new Set(groups.map((g) => g.group.dn));
          setSearchResults(response.groups.filter((g) => !existingDNs.has(g.dn)));
          setIsSearchOpen(true);
        }
      } catch {
        setSearchResults([]);
      } finally {
        setIsSearching(false);
      }
    }, 300);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [searchQuery, groups]);

  const addGroupToTable = (group: Group) => {
    const newGroupStatus: UserGroupStatus = { group, isMember: true, membershipType: 'direct' };
    setGroups((prev) => [...prev, newGroupStatus].sort((a, b) => a.group.cn.localeCompare(b.group.cn)));
    setPendingChanges((prev) => {
      const next = new Map(prev);
      next.set(group.cn, 'add');
      return next;
    });
    setSearchQuery('');
    setSearchResults([]);
    setIsSearchOpen(false);
  };

  const toggleMembership = (groupCN: string, currentStatus: boolean) => {
    setGroups((prev) =>
      prev.map((g) => g.group.cn === groupCN ? { ...g, isMember: !currentStatus } : g)
    );
    setPendingChanges((prev) => {
      const next = new Map(prev);
      const originalMember = user.memberOf?.some((dn) =>
        dn.toLowerCase().includes(`cn=${groupCN.toLowerCase()}`)
      );
      if (originalMember) {
        if (currentStatus) next.set(groupCN, 'remove');
        else next.delete(groupCN);
      } else {
        if (!currentStatus) next.set(groupCN, 'add');
        else next.delete(groupCN);
      }
      return next;
    });
  };

  const handleSave = async () => {
    if (pendingChanges.size === 0) {
      showNotification('No changes to save', 'info');
      return;
    }

    setIsSaving(true);
    let successCount = 0;
    const errors: string[] = [];

    for (const [groupName, action] of pendingChanges) {
      const response = action === 'add'
        ? await api.addUserToGroup(user.sAMAccountName, groupName)
        : await api.removeUserFromGroup(user.sAMAccountName, groupName);

      if (response.success) {
        successCount++;
      } else {
        errors.push(`${groupName}: ${response.error || 'Unknown error'}`);
      }
    }

    setIsSaving(false);
    setPendingChanges(new Map());

    if (errors.length === 0) {
      showNotification(`Successfully updated ${successCount} group membership(s)`, 'success');
    } else if (successCount > 0) {
      showNotification(`Updated ${successCount} membership(s). Errors: ${errors.join('; ')}`, 'warning', 15000);
    } else {
      showNotification(`Failed to update memberships: ${errors.join('; ')}`, 'error', 15000);
    }

    if (onUpdate) onUpdate();
  };

  const columns: ColumnDef<UserGroupStatus>[] = [
    {
      accessorKey: 'group.cn',
      header: 'Name',
      cell: ({ row }) => (
        <span className="font-medium text-foreground">{row.original.group.cn}</span>
      ),
    },
    {
      accessorKey: 'group.description',
      header: 'Description',
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {row.original.group.description || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'membershipType',
      header: () => <div className="text-center">Group Type</div>,
      cell: ({ row }) => (
        <div className="flex justify-center">
          <Badge
            variant="outline"
            className={
              row.original.membershipType === 'direct'
                ? 'bg-primary/10 text-primary border-primary/30'
                : 'bg-muted text-muted-foreground border-border'
            }
          >
            {row.original.membershipType}
          </Badge>
        </div>
      ),
    },
    {
      accessorKey: 'isMember',
      header: () => <div className="text-center">Status</div>,
      cell: ({ row }) => (
        <div className="flex justify-center">
          <Checkbox
            checked={row.original.isMember}
            onCheckedChange={() =>
              toggleMembership(row.original.group.cn, row.original.isMember)
            }
          />
        </div>
      ),
    },
  ];

  const table = useReactTable({
    data: groups,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg">Group Membership</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Group search */}
        <div className="relative" ref={searchRef}>
          <div className="relative flex items-center">
            <Search className="absolute left-3 w-4 h-4 text-muted-foreground pointer-events-none" />
            <Input
              type="text"
              placeholder="Search groups to add..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onFocus={() => searchResults.length > 0 && setIsSearchOpen(true)}
              className="pl-10"
            />
            {isSearching && (
              <div className="absolute right-3 w-4 h-4 rounded-full border-2 border-muted border-t-primary animate-spin" />
            )}
          </div>

          {isSearchOpen && searchResults.length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-card rounded-lg shadow-xl max-h-60 overflow-y-auto z-50 border border-border">
              {searchResults.map((group) => (
                <button
                  key={group.dn}
                  className="flex flex-col gap-1 px-4 py-3 w-full text-left hover:bg-muted transition-colors border-b border-border last:border-0"
                  onClick={() => addGroupToTable(group)}
                >
                  <span className="text-sm font-medium text-foreground">{group.cn}</span>
                  <span className="text-xs text-muted-foreground">{group.description || 'No description'}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Data table */}
        <div className="rounded-md border border-border overflow-x-auto">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id} className="bg-muted/50">
                  {headerGroup.headers.map((header) => (
                    <TableHead key={header.id} className="font-semibold">
                      {header.isPlaceholder
                        ? null
                        : flexRender(header.column.columnDef.header, header.getContext())}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {table.getRowModel().rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={columns.length} className="text-center text-muted-foreground py-8">
                    No group memberships found
                  </TableCell>
                </TableRow>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={pendingChanges.has(row.original.group.cn) ? 'bg-amber-50' : ''}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-start gap-4 pt-1">
          <Button
            onClick={handleSave}
            disabled={isSaving || pendingChanges.size === 0}
          >
            {isSaving ? 'Saving...' : 'Save'}
          </Button>
          {pendingChanges.size > 0 && (
            <span className="text-sm font-medium text-amber-700">
              {pendingChanges.size} pending change(s)
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
