import { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, Navigate, Link } from 'react-router-dom';
import { Users } from 'lucide-react';
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from '@tanstack/react-table';
import { useAuth } from '../contexts/AuthContext';
import { Sidebar } from '../components/Sidebar';
import { GroupSearch } from '../components/GroupSearch';
import type { Group, GroupMember } from '../types';
import api from '../services/api';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

export function GroupPage() {
  const { groupName } = useParams<{ groupName: string }>();
  const { isAuthenticated, isLoading, canSearch } = useAuth();
  const [group, setGroup] = useState<Group | null>(null);
  const [members, setMembers] = useState<GroupMember[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoadingGroup, setIsLoadingGroup] = useState(true);

  const loadGroup = useCallback(async () => {
    // No group in the URL is the browse landing state, reached from the sidebar tab:
    // the search box is shown and nothing is fetched until a group is picked.
    if (!groupName) {
      setGroup(null);
      setMembers([]);
      setError(null);
      setIsLoadingGroup(false);
      return;
    }

    setIsLoadingGroup(true);
    try {
      const response = await api.getGroup(groupName);
      if (response.success && response.group) {
        setGroup(response.group);
        setMembers(response.members ?? []);
        setTruncated(response.truncated ?? false);
        setError(null);
      } else {
        setGroup(null);
        setMembers([]);
        setError(response.error || 'Group not found');
      }
    } catch {
      setGroup(null);
      setMembers([]);
      setError('Failed to load group data');
    } finally {
      setIsLoadingGroup(false);
    }
  }, [groupName]);

  useEffect(() => {
    if (isAuthenticated) {
      loadGroup();
    }
  }, [isAuthenticated, loadGroup]);

  // Memoised for the same reason as the membership table: useReactTable compares
  // `columns` and `data` by identity and rebuilds the row model when either changes.
  const columns: ColumnDef<GroupMember>[] = useMemo(
    () => [
      {
        accessorKey: 'displayName',
        header: 'Name',
        cell: ({ row }) => {
          const member = row.original;
          const label = member.displayName || member.cn || member.dn;

          // Nested groups link to their own page; users link to their profile. A member
          // without a username has no profile route, so it stays plain text.
          if (member.isGroup) {
            return (
              <Link
                to={`/group/${encodeURIComponent(member.cn)}`}
                className="font-medium text-primary hover:underline"
              >
                {label}
              </Link>
            );
          }
          if (member.sAMAccountName) {
            return (
              <Link
                to={`/user/${encodeURIComponent(member.sAMAccountName)}`}
                className="font-medium text-primary hover:underline"
              >
                {label}
              </Link>
            );
          }
          return <span className="font-medium text-foreground">{label}</span>;
        },
      },
      {
        accessorKey: 'sAMAccountName',
        header: 'Username',
        cell: ({ row }) => (
          <span className="text-muted-foreground font-mono text-xs">
            {row.original.sAMAccountName || '-'}
          </span>
        ),
      },
      {
        accessorKey: 'mail',
        header: 'Email',
        cell: ({ row }) =>
          row.original.mail ? (
            <a href={`mailto:${row.original.mail}`} className="text-sm">
              {row.original.mail}
            </a>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        accessorKey: 'isGroup',
        header: () => <div className="text-center">Type</div>,
        cell: ({ row }) => (
          <div className="flex justify-center">
            <Badge
              variant="outline"
              className={
                row.original.isGroup
                  ? 'bg-amber-600/10 text-amber-700 border-amber-600/40 dark:text-amber-500'
                  : 'bg-primary/10 text-primary border-primary/30'
              }
            >
              {row.original.isGroup ? 'group' : 'user'}
            </Badge>
          </div>
        ),
      },
    ],
    []
  );

  const table = useReactTable({
    data: members,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center gap-4 flex-col text-muted-foreground">
        <div className="w-10 h-10 rounded-full border-3 border-muted border-t-primary animate-spin" />
        <p>Loading...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar />

      <main className="flex-1 ml-64 flex flex-col h-screen overflow-hidden bg-background">
        {/* Header */}
        <header className="flex items-center justify-between px-8 py-5 bg-card border-b border-border shrink-0">
          <div className="flex items-center gap-8 flex-1">
            <h2 className="text-xl font-semibold text-foreground whitespace-nowrap">Groups</h2>
            <GroupSearch />
          </div>
        </header>

        {!canSearch ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <h3 className="text-xl font-semibold text-foreground mb-2">Not available</h3>
            <p className="text-sm text-muted-foreground">
              You do not have permission to browse groups.
            </p>
          </div>
        ) : !groupName ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <Users className="w-10 h-10 text-muted-foreground mb-4" />
            <h3 className="text-xl font-semibold text-foreground mb-2">Search for a group</h3>
            <p className="text-sm text-muted-foreground">
              Use the search box above to find a group and view its members.
            </p>
          </div>
        ) : isLoadingGroup ? (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 text-muted-foreground">
            <div className="w-10 h-10 rounded-full border-3 border-muted border-t-primary animate-spin" />
            <p>Loading group data...</p>
          </div>
        ) : group ? (
          <div className="flex-1 overflow-y-auto p-8 flex flex-col gap-6">
            {/* Group card */}
            <Card>
              <CardHeader className="pb-0">
                <CardTitle className="text-lg">Group</CardTitle>
              </CardHeader>
              <CardContent className="pt-5">
                <div className="flex items-start gap-5 pb-6">
                  <div className="w-20 h-20 shrink-0 rounded-full bg-primary flex items-center justify-center text-primary-foreground">
                    <Users className="w-9 h-9" />
                  </div>

                  <div className="flex flex-col gap-1">
                    <h3 className="text-2xl font-semibold text-foreground">{group.cn}</h3>
                    <p className="text-sm text-muted-foreground">
                      {group.description || 'No description'}
                    </p>
                  </div>
                </div>

                <Separator className="mb-6" />

                <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-5">
                  <GroupField label="Name" value={group.cn} />
                  <GroupField label="Account Name" value={group.sAMAccountName} />
                  <GroupField label="Members" value={String(members.length)} />

                  <div className="col-span-full flex flex-col gap-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                      DN
                    </label>
                    <span className="font-mono text-sm text-muted-foreground bg-muted px-3 py-2 rounded-md break-all">
                      {group.dn}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Members */}
            <Card>
              <CardHeader className="pb-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <CardTitle className="text-lg">Members ({members.length})</CardTitle>
                  {truncated && (
                    <Badge variant="outline" className="bg-amber-50 text-amber-800 border-amber-200">
                      Showing the first {members.length} members
                    </Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent>
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
                          <TableCell
                            colSpan={columns.length}
                            className="text-center text-muted-foreground py-8"
                          >
                            This group has no members
                          </TableCell>
                        </TableRow>
                      ) : (
                        table.getRowModel().rows.map((row) => (
                          <TableRow key={row.id}>
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
              </CardContent>
            </Card>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <h3 className="text-xl font-semibold text-foreground mb-2">Group not found</h3>
            <p className="text-sm text-muted-foreground">
              {error || `The group "${groupName}" could not be found in Active Directory.`}
            </p>
          </div>
        )}
      </main>
    </div>
  );
}

function GroupField({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
        {label}
      </label>
      <span className="text-sm text-foreground">{value || '-'}</span>
    </div>
  );
}
