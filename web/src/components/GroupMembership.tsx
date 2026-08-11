import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
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
import { useAuth } from '../contexts/AuthContext';
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
  // Direct-only by default: inherited groups are informational and can bulk out the
  // table considerably on users nested deep in the hierarchy.
  const [showNested, setShowNested] = useState(false);
  const { showNotification } = useNotification();
  const { canSearch } = useAuth();
  const searchRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // Mirrors `groups` so the debounced search can read the current rows without
  // taking a dependency on an array that is rebuilt on every load.
  const groupsRef = useRef<UserGroupStatus[]>([]);
  groupsRef.current = groups;

  const extractCNFromDN = (dn: string): string => {
    const match = dn.match(/^CN=([^,]+)/i);
    return match ? match[1] : dn;
  };

  // Resolves only the groups this user belongs to, rather than listing the directory.
  // Purely decorative: it supplies descriptions the DN-derived fallback below lacks,
  // so a failure degrades the table rather than emptying it.
  const loadUserGroupDetails = useCallback(async () => {
    const memberOf = user.memberOf;
    if (!memberOf || memberOf.length === 0) {
      setAllGroups([]);
      return;
    }

    try {
      // nested=true so groups inherited through another group come back too; the
      // user object's memberOf only lists direct memberships.
      const response = await api.resolveGroups(memberOf, true);
      if (response.success && response.groups) {
        setAllGroups(response.groups);
      }
    } catch {
      console.error('Failed to resolve group details');
    }
  }, [user.memberOf]);

  const loadUserGroups = useCallback(() => {
    if (!user.memberOf) {
      setGroups([]);
      return;
    }

    const directGroups: UserGroupStatus[] = user.memberOf.map((groupDN) => {
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

    // Groups the backend reached by walking the nesting chain. They are not on the
    // user object, so they only appear when the resolve call succeeded.
    const directDNs = new Set(
      user.memberOf.map((dn) => dn.toLowerCase())
    );
    const nestedGroups: UserGroupStatus[] = allGroups
      .filter((g) => g.nested && !directDNs.has(g.dn.toLowerCase()))
      .map((g) => ({
        group: g,
        isMember: true,
        membershipType: 'nested' as const,
      }));

    setGroups(
      [...directGroups, ...nestedGroups].sort((a, b) =>
        a.group.cn.localeCompare(b.group.cn)
      )
    );
  }, [user.memberOf, allGroups]);

  useEffect(() => {
    loadUserGroupDetails();
  }, [loadUserGroupDetails]);

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
    // Runs even when allGroups is empty: users without listing permission still see
    // their own memberships, rendered from the DN-derived fallback in loadUserGroups.
    loadUserGroups();
  }, [allGroups, user.memberOf, loadUserGroups]);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    if (!canSearch || searchQuery.length < 2) {
      // Replacing with a fresh [] on every run would re-render, which re-creates the
      // `groups` array this effect depends on, looping forever. Only clear if needed.
      setSearchResults((prev) => (prev.length === 0 ? prev : []));
      return;
    }

    debounceRef.current = setTimeout(async () => {
      setIsSearching(true);
      try {
        const response = await api.searchGroups(searchQuery);
        if (response.success && response.groups) {
          // Read the current rows from the ref rather than depending on `groups`:
          // that array is rebuilt on every load, and depending on it here restarts
          // the search whenever the table re-renders.
          const existingDNs = new Set(groupsRef.current.map((g) => g.group.dn));
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
  }, [searchQuery, canSearch]);

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

  // Stable identity so the memoised columns below are not rebuilt on every render.
  const toggleMembership = useCallback((groupCN: string, currentStatus: boolean) => {
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
  }, [user.memberOf]);

  // Discards every unsaved change. Rows added since the last save are dropped outright;
  // rows that only had their checkbox toggled are restored to being a member, which is
  // the state anything already in the table started from.
  const handleCancel = () => {
    if (pendingChanges.size === 0) return;

    const added = new Set(
      [...pendingChanges].filter(([, action]) => action === 'add').map(([cn]) => cn)
    );
    const addedButNotSaved = new Set(
      [...added].filter(
        (cn) =>
          !user.memberOf?.some((dn) => extractCNFromDN(dn).toLowerCase() === cn.toLowerCase())
      )
    );

    setGroups((prev) =>
      prev
        .filter((g) => !addedButNotSaved.has(g.group.cn))
        .map((g) => (g.isMember ? g : { ...g, isMember: true }))
    );
    setPendingChanges(new Map());
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

  // Also memoised: useReactTable compares `columns` by identity as well.
  const columns: ColumnDef<UserGroupStatus>[] = useMemo(() => [
    {
      accessorKey: 'group.cn',
      header: 'Name',
      cell: ({ row }) => {
        // The group page reads the same gated endpoints as search, so users without
        // that permission get plain text rather than a link into a 403.
        if (!canSearch) {
          return <span className="font-medium text-foreground">{row.original.group.cn}</span>;
        }
        return (
          <Link
            to={`/group/${encodeURIComponent(row.original.group.cn)}`}
            className="font-medium text-primary hover:underline"
          >
            {row.original.group.cn}
          </Link>
        );
      },
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
                : 'bg-amber-600/10 text-amber-700 border-amber-600/40 dark:text-amber-500'
            }
            title={
              row.original.membershipType === 'nested'
                ? 'Inherited through another group'
                : undefined
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
      cell: ({ row }) => {
        // Inherited membership lives on the parent group, not the user, so it cannot
        // be revoked here — removing the user from this group would be a no-op.
        const isNested = row.original.membershipType === 'nested';
        return (
          <div className="flex justify-center">
            <Checkbox
              checked={row.original.isMember}
              disabled={isNested}
              title={
                isNested
                  ? 'Inherited membership — change it on the parent group'
                  : undefined
              }
              onCheckedChange={() =>
                toggleMembership(row.original.group.cn, row.original.isMember)
              }
            />
          </div>
        );
      },
    },
  ], [toggleMembership, canSearch]);

  // groups always holds both kinds; the toggle only narrows what is rendered, so
  // flipping it is instant and the search dedupe below still sees nested memberships.
  //
  // Memoised because useReactTable treats `data` by identity: handing it a freshly
  // filtered array on every render makes it rebuild the row model and re-render,
  // which loops until the tab hangs.
  const { visibleGroups, nestedCount } = useMemo(() => {
    const direct = groups.filter((g) => g.membershipType === 'direct');
    return {
      visibleGroups: showNested ? groups : direct,
      nestedCount: groups.length - direct.length,
    };
  }, [groups, showNested]);

  const table = useReactTable({
    data: visibleGroups,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-lg">Group Membership</CardTitle>

          {/* Scope toggle. Rendered only when there is something to reveal, so users
              with no inherited memberships are not offered an inert control. */}
          {nestedCount > 0 && (
            <div className="inline-flex rounded-md border border-border p-0.5" role="group">
              <Button
                type="button"
                size="sm"
                variant={showNested ? 'ghost' : 'secondary'}
                aria-pressed={!showNested}
                className="h-7 px-3 text-xs"
                onClick={() => setShowNested(false)}
              >
                Direct only
              </Button>
              <Button
                type="button"
                size="sm"
                variant={showNested ? 'secondary' : 'ghost'}
                aria-pressed={showNested}
                className="h-7 px-3 text-xs"
                onClick={() => setShowNested(true)}
              >
                All ({groups.length})
              </Button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Group search — hidden for users without search permission */}
        {canSearch && (
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
        )}

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
                    {nestedCount > 0
                      ? 'No direct group memberships found — switch to All to see inherited groups'
                      : 'No group memberships found'}
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
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isSaving || pendingChanges.size === 0}
          >
            Cancel
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
