import { useState, useEffect, useRef } from 'react';
import { Search, UserPlus } from 'lucide-react';
import api from '../services/api';
import { useNotification } from '../contexts/NotificationContext';
import type { SearchEntry } from '../types';
import { Input } from '@/components/ui/input';

interface GroupMemberAddProps {
  groupName: string;
  /** sAMAccountNames already in the group, so they are not offered a second time. */
  memberUsernames: string[];
  /** Called after the server accepts the change, so the page can reload the members. */
  onAdded: () => void;
}

export function GroupMemberAdd({ groupName, memberUsernames, onAdded }: GroupMemberAddProps) {
  const { showNotification } = useNotification();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchEntry[]>([]);
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
      setResults([]);
      return;
    }

    debounceRef.current = setTimeout(async () => {
      setIsSearching(true);
      try {
        const response = await api.searchUsers(query);
        if (response.success && response.entries) {
          setResults(response.entries);
          setIsOpen(true);
        }
      } catch {
        setResults([]);
      } finally {
        setIsSearching(false);
      }
    }, 300);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query]);

  const memberSet = new Set(memberUsernames.map((name) => name.toLowerCase()));

  const handleAdd = async (entry: SearchEntry) => {
    const username = entry.attributes.sAMAccountName?.[0];
    if (!username || isAdding) return;

    const label = entry.attributes.displayName?.[0] || username;
    setIsAdding(true);
    const result = await api.addGroupMember(groupName, username);
    setIsAdding(false);

    if (result.success) {
      showNotification(`${label} added to ${groupName}.`, 'success');
      setQuery('');
      setResults([]);
      setIsOpen(false);
      onAdded();
    } else {
      showNotification(result.error || result.message || 'Failed to add member.', 'error');
    }
  };

  return (
    <div className="relative w-full max-w-[420px]" ref={wrapperRef}>
      <div className="relative flex items-center">
        <Search className="absolute left-4 w-4 h-4 text-muted-foreground pointer-events-none" />
        <Input
          type="text"
          aria-label="Add a member"
          placeholder="Add a member by name or email..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => results.length > 0 && setIsOpen(true)}
          disabled={isAdding}
          className="pl-11"
        />
        {isSearching && (
          <div className="absolute right-4 w-4 h-4 rounded-full border-2 border-muted border-t-primary animate-spin" />
        )}
      </div>

      {isOpen && results.length > 0 && (
        <div className="absolute top-full left-0 right-0 mt-2 bg-card rounded-lg shadow-xl max-h-72 overflow-y-auto z-50 border border-border">
          {results.map((entry) => {
            const username = entry.attributes.sAMAccountName?.[0];
            const alreadyMember = !!username && memberSet.has(username.toLowerCase());
            const name = entry.attributes.displayName?.[0] || entry.attributes.cn?.[0] || 'Unknown';

            return (
              <button
                key={entry.dn}
                type="button"
                // An entry without a username cannot be addressed by the endpoint.
                disabled={!username || alreadyMember || isAdding}
                className="flex items-center gap-3 px-4 py-3 w-full text-left hover:bg-muted transition-colors border-b border-border last:border-0 disabled:opacity-50 disabled:hover:bg-transparent"
                onClick={() => handleAdd(entry)}
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
          })}
        </div>
      )}
    </div>
  );
}
