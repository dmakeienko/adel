import { useState, useEffect, useRef } from 'react';
import { Search, User, UserPlus, Users } from 'lucide-react';
import api from '../services/api';
import { useNotification } from '../contexts/NotificationContext';
import type { Group, GroupMember, SearchEntry } from '../types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type AddMode = 'user' | 'group';

interface GroupMemberAddProps {
  /** The group being managed. */
  group: Group;
  /** Its current members, so people and groups already in it are not offered again. */
  members: GroupMember[];
  /** Called after the server accepts the change, so the page can reload the members. */
  onAdded: () => void;
}

export function GroupMemberAdd({ group, members, onAdded }: GroupMemberAddProps) {
  const { showNotification } = useNotification();
  const [mode, setMode] = useState<AddMode>('user');
  const [query, setQuery] = useState('');
  const [userResults, setUserResults] = useState<SearchEntry[]>([]);
  const [groupResults, setGroupResults] = useState<Group[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [isAdding, setIsAdding] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    // Two characters matches the server's search minimum.
    if (query.length < 2) {
      setUserResults([]);
      setGroupResults([]);
      return;
    }

    debounceRef.current = setTimeout(async () => {
      setIsSearching(true);
      try {
        if (mode === 'user') {
          const response = await api.searchUsers(query);
          if (response.success && response.entries) {
            setUserResults(response.entries);
            setIsOpen(true);
          }
        } else {
          const response = await api.searchGroups(query);
          if (response.success && response.groups) {
            setGroupResults(response.groups);
            setIsOpen(true);
          }
        }
      } catch {
        setUserResults([]);
        setGroupResults([]);
      } finally {
        setIsSearching(false);
      }
    }, 300);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query, mode]);

  const switchMode = (next: AddMode) => {
    if (next === mode) return;
    setMode(next);
    setQuery('');
    setUserResults([]);
    setGroupResults([]);
    setIsOpen(false);
  };

  const finish = (message: string) => {
    showNotification(message, 'success');
    setQuery('');
    setUserResults([]);
    setGroupResults([]);
    setIsOpen(false);
    onAdded();
  };

  const memberUsernames = new Set(
    members
      .filter((m) => !m.isGroup && m.sAMAccountName)
      .map((m) => m.sAMAccountName!.toLowerCase())
  );
  const memberGroupDNs = new Set(members.filter((m) => m.isGroup).map((m) => m.dn.toLowerCase()));

  const handleAddUser = async (entry: SearchEntry) => {
    const username = entry.attributes.sAMAccountName?.[0];
    if (!username || isAdding) return;

    const label = entry.attributes.displayName?.[0] || username;
    setIsAdding(true);
    const result = await api.addGroupMember(group.cn, username);
    setIsAdding(false);

    if (result.success) {
      finish(`${label} added to ${group.cn}.`);
    } else {
      showNotification(result.error || result.message || 'Failed to add member.', 'error');
    }
  };

  const handleAddGroup = async (candidate: Group) => {
    if (isAdding) return;

    setIsAdding(true);
    // sAMAccountName is unique in the domain, whereas a CN can repeat across OUs and
    // would let the server pick the wrong group.
    const result = await api.addMemberGroup(group.cn, candidate.sAMAccountName || candidate.cn);
    setIsAdding(false);

    if (result.success) {
      finish(`Group ${candidate.cn} added to ${group.cn}.`);
    } else {
      showNotification(result.error || result.message || 'Failed to add group.', 'error');
    }
  };

  const hasResults = mode === 'user' ? userResults.length > 0 : groupResults.length > 0;

  return (
    <div className="w-full max-w-[420px]">
      <div className="relative" ref={wrapperRef}>
        <div className="relative flex items-center">
          <Search className="absolute left-4 w-4 h-4 text-muted-foreground pointer-events-none" />
          <Input
            type="text"
            aria-label={mode === 'user' ? 'Add a member' : 'Add a group'}
            placeholder={
              mode === 'user' ? 'Add a member by name or email...' : 'Add a group by name...'
            }
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onFocus={() => hasResults && setIsOpen(true)}
            disabled={isAdding}
            className="pl-11 pr-24"
          />
          {isSearching && (
            <div className="absolute right-24 w-4 h-4 rounded-full border-2 border-muted border-t-primary animate-spin" />
          )}
          {/* One toggle rather than two buttons: its label names what is being searched, and
              pressing it flips between users and groups. The accessible name stays constant
              and the state lives in aria-pressed, as for any toggle button. */}
          <Button
            type="button"
            size="sm"
            variant={mode === 'group' ? 'default' : 'outline'}
            aria-label="Search groups"
            aria-pressed={mode === 'group'}
            disabled={isAdding}
            onClick={() => switchMode(mode === 'user' ? 'group' : 'user')}
            className="absolute right-1.5 top-1/2 h-7 -translate-y-1/2 px-2 text-xs"
          >
            {mode === 'user' ? <User className="w-3.5 h-3.5" /> : <Users className="w-3.5 h-3.5" />}
            {mode === 'user' ? 'Users' : 'Groups'}
          </Button>
        </div>

        {isOpen && hasResults && (
          <div className="absolute top-full left-0 right-0 mt-2 bg-card rounded-lg shadow-xl max-h-72 overflow-y-auto z-50 border border-border">
            {mode === 'user'
              ? userResults.map((entry) => {
                  const username = entry.attributes.sAMAccountName?.[0];
                  const alreadyMember = !!username && memberUsernames.has(username.toLowerCase());
                  const name =
                    entry.attributes.displayName?.[0] || entry.attributes.cn?.[0] || 'Unknown';

                  return (
                    <button
                      key={entry.dn}
                      type="button"
                      // An entry without a username cannot be addressed by the endpoint.
                      disabled={!username || alreadyMember || isAdding}
                      className="flex items-center gap-3 px-4 py-3 w-full text-left hover:bg-muted transition-colors border-b border-border last:border-0 disabled:opacity-50 disabled:hover:bg-transparent"
                      onClick={() => handleAddUser(entry)}
                    >
                      <UserPlus className="w-4 h-4 shrink-0 text-muted-foreground" />
                      <div className="flex-1 flex flex-col overflow-hidden">
                        <span className="text-sm font-medium text-foreground truncate">{name}</span>
                        <span className="text-xs text-muted-foreground truncate">
                          {entry.attributes.mail?.[0] || 'No email'}
                        </span>
                      </div>
                      <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded font-mono shrink-0">
                        {alreadyMember ? 'member' : username}
                      </span>
                    </button>
                  );
                })
              : groupResults.map((candidate) => {
                  const isSelf = candidate.dn.toLowerCase() === group.dn.toLowerCase();
                  const alreadyMember = memberGroupDNs.has(candidate.dn.toLowerCase());
                  const tag = isSelf ? 'this group' : alreadyMember ? 'member' : 'group';

                  return (
                    <button
                      key={candidate.dn}
                      type="button"
                      // A group cannot contain itself, and nesting it twice is a no-op.
                      disabled={isSelf || alreadyMember || isAdding}
                      className="flex items-center gap-3 px-4 py-3 w-full text-left hover:bg-muted transition-colors border-b border-border last:border-0 disabled:opacity-50 disabled:hover:bg-transparent"
                      onClick={() => handleAddGroup(candidate)}
                    >
                      <Users className="w-4 h-4 shrink-0 text-muted-foreground" />
                      <div className="flex-1 flex flex-col overflow-hidden">
                        <span className="text-sm font-medium text-foreground truncate">
                          {candidate.cn}
                        </span>
                        <span className="text-xs text-muted-foreground truncate">
                          {candidate.description || 'No description'}
                        </span>
                      </div>
                      <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded font-mono shrink-0">
                        {tag}
                      </span>
                    </button>
                  );
                })}
          </div>
        )}
      </div>

    </div>
  );
}
