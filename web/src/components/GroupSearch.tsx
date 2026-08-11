import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Users } from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import type { Group } from '../types';
import { Input } from '@/components/ui/input';

export function GroupSearch() {
  const { canSearch } = useAuth();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Group[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const navigate = useNavigate();
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

    // Two characters matches the server's minimum; shorter queries are refused there.
    if (!canSearch || query.length < 2) {
      setResults([]);
      return;
    }

    debounceRef.current = setTimeout(async () => {
      setIsLoading(true);
      try {
        const response = await api.searchGroups(query);
        if (response.success && response.groups) {
          setResults(response.groups);
          setIsOpen(true);
        }
      } catch {
        setResults([]);
      } finally {
        setIsLoading(false);
      }
    }, 300);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query, canSearch]);

  const handleSelect = (group: Group) => {
    navigate(`/group/${encodeURIComponent(group.cn)}`);
    setQuery('');
    setIsOpen(false);
    setResults([]);
  };

  if (!canSearch) {
    return null;
  }

  return (
    <div className="relative w-full max-w-[500px]" ref={wrapperRef}>
      <div className="relative flex items-center">
        <Search className="absolute left-4 w-5 h-5 text-muted-foreground pointer-events-none" />
        <Input
          type="text"
          placeholder="Search groups by name..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => results.length > 0 && setIsOpen(true)}
          className="pl-12"
        />
        {isLoading && (
          <div className="absolute right-4 w-5 h-5 rounded-full border-2 border-muted border-t-primary animate-spin" />
        )}
      </div>

      {isOpen && results.length > 0 && (
        <div className="absolute top-full left-0 right-0 mt-2 bg-card rounded-lg shadow-xl max-h-80 overflow-y-auto z-50 border border-border">
          {results.map((group) => (
            <button
              key={group.dn}
              className="flex items-center gap-3 px-4 py-3 w-full text-left hover:bg-muted transition-colors border-b border-border last:border-0"
              onClick={() => handleSelect(group)}
            >
              <div className="w-10 h-10 rounded-full bg-primary flex items-center justify-center text-primary-foreground shrink-0">
                <Users className="w-5 h-5" />
              </div>
              <div className="flex-1 flex flex-col overflow-hidden">
                <span className="text-sm font-medium text-foreground truncate">
                  {group.cn}
                </span>
                <span className="text-xs text-muted-foreground truncate">
                  {group.description || 'No description'}
                </span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
