import { useState, useEffect, useMemo } from 'react';
import { Navigate, Link } from 'react-router-dom';
import { UsersRound, Search } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { Sidebar } from '../components/Sidebar';
import type { GroupMember, TeamGroup } from '../types';
import api from '../services/api';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

/** Label used for sorting and filtering a member row. */
function memberLabel(member: GroupMember): string {
  return member.displayName || member.cn || member.sAMAccountName || member.dn;
}

export function TeamPage() {
  const { isAuthenticated, isLoading, isLead, leadGroups } = useAuth();
  const [teams, setTeams] = useState<TeamGroup[]>([]);
  const [memberCount, setMemberCount] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [isLoadingTeam, setIsLoadingTeam] = useState(true);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    // A non-lead has no team, and the endpoint would return an empty one, so the
    // request is skipped entirely rather than made and discarded.
    if (!isAuthenticated || !isLead) {
      return;
    }

    let cancelled = false;

    // Wrapped in an async function so no setState runs synchronously in the effect
    // body: the first state update happens after the request settles.
    const load = async () => {
      try {
        const response = await api.getTeam();
        if (cancelled) {
          return;
        }
        if (response.success) {
          setTeams(response.groups ?? []);
          setMemberCount(response.memberCount ?? 0);
          setError(null);
        } else {
          setTeams([]);
          setError(response.error || 'Failed to load your team');
        }
      } catch {
        if (!cancelled) {
          setTeams([]);
          setError('Failed to load your team');
        }
      } finally {
        if (!cancelled) {
          setIsLoadingTeam(false);
        }
      }
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, isLead]);

  // Filtering is client-side: the team is already bounded by the lead's scope, so it is
  // a small list and re-querying the directory on each keystroke would be wasteful.
  const visibleTeams = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return teams;
    }
    return teams
      .map((team) => ({
        ...team,
        members: team.members.filter((member) =>
          [memberLabel(member), member.sAMAccountName, member.mail]
            .filter(Boolean)
            .some((field) => field!.toLowerCase().includes(needle))
        ),
      }))
      .filter((team) => team.members.length > 0);
  }, [teams, filter]);

  const visibleCount = useMemo(() => {
    const seen = new Set<string>();
    for (const team of visibleTeams) {
      for (const member of team.members) {
        seen.add(member.dn.toLowerCase());
      }
    }
    return seen.size;
  }, [visibleTeams]);

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
        <header className="flex items-center justify-between px-8 py-5 bg-card border-b border-border shrink-0">
          <div className="flex items-center gap-8 flex-1">
            <h2 className="text-xl font-semibold text-foreground whitespace-nowrap">Team</h2>
            {isLead && teams.length > 0 && (
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  type="text"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Filter by name, username or email..."
                  className="pl-9"
                  aria-label="Filter team members"
                />
              </div>
            )}
          </div>
        </header>

        {!isLead ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <h3 className="text-xl font-semibold text-foreground mb-2">Not available</h3>
            <p className="text-sm text-muted-foreground">
              You do not lead any groups, so there is no team to show.
            </p>
          </div>
        ) : isLoadingTeam ? (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 text-muted-foreground">
            <div className="w-10 h-10 rounded-full border-3 border-muted border-t-primary animate-spin" />
            <p>Loading your team...</p>
          </div>
        ) : error ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <h3 className="text-xl font-semibold text-foreground mb-2">
              Could not load your team
            </h3>
            <p className="text-sm text-muted-foreground">{error}</p>
          </div>
        ) : teams.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <UsersRound className="w-10 h-10 text-muted-foreground mb-4" />
            <h3 className="text-xl font-semibold text-foreground mb-2">No groups found</h3>
            <p className="text-sm text-muted-foreground">
              No groups matched {leadGroups.join(', ') || 'your leadership scope'}.
            </p>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-8 flex flex-col gap-6">
            {/* Scope summary, so a lead can see which wildcards this view covers. */}
            <Card>
              <CardHeader className="pb-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <CardTitle className="text-lg">
                    {filter.trim()
                      ? `${visibleCount} of ${memberCount} people`
                      : `${memberCount} ${memberCount === 1 ? 'person' : 'people'}`}
                  </CardTitle>
                  <div className="flex flex-wrap gap-1.5">
                    {leadGroups.map((wildcard) => (
                      <Badge
                        key={wildcard}
                        variant="outline"
                        className="bg-primary/10 text-primary border-primary/30 font-mono text-xs"
                      >
                        {wildcard}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="pt-2">
                <p className="text-sm text-muted-foreground">
                  Everyone in the {teams.length === 1 ? 'group' : `${teams.length} groups`} you
                  lead. People in more than one group are counted once.
                </p>
              </CardContent>
            </Card>

            {visibleTeams.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center text-muted-foreground">
                  No team members match "{filter}".
                </CardContent>
              </Card>
            ) : (
              visibleTeams.map((team) => (
                <TeamGroupCard key={team.group.dn} team={team} />
              ))
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function TeamGroupCard({ team }: { team: TeamGroup }) {
  const { group, members, truncated } = team;

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-lg">
            <Link to={`/group/${encodeURIComponent(group.cn)}`} className="hover:underline">
              {group.cn}
            </Link>{' '}
            <span className="text-muted-foreground font-normal">({members.length})</span>
          </CardTitle>
          {truncated && (
            <Badge
              variant="outline"
              className="bg-amber-50 text-amber-800 border-amber-200"
            >
              Showing the first {members.length} members
            </Badge>
          )}
        </div>
        {group.description && (
          <p className="text-sm text-muted-foreground">{group.description}</p>
        )}
      </CardHeader>
      <CardContent>
        <div className="rounded-md border border-border overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/50">
                <TableHead className="font-semibold">Name</TableHead>
                <TableHead className="font-semibold">Username</TableHead>
                <TableHead className="font-semibold">Email</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {members.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-muted-foreground py-8">
                    This group has no members
                  </TableCell>
                </TableRow>
              ) : (
                members.map((member) => (
                  <TableRow key={member.dn}>
                    <TableCell>
                      {member.sAMAccountName ? (
                        <Link
                          to={`/user/${encodeURIComponent(member.sAMAccountName)}`}
                          className="font-medium text-primary hover:underline"
                        >
                          {memberLabel(member)}
                        </Link>
                      ) : (
                        <span className="font-medium text-foreground">
                          {memberLabel(member)}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-muted-foreground font-mono text-xs">
                        {member.sAMAccountName || '-'}
                      </span>
                    </TableCell>
                    <TableCell>
                      {member.mail ? (
                        <a href={`mailto:${member.mail}`} className="text-sm">
                          {member.mail}
                        </a>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
