import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import api from '../services/api';
import type { SearchEntry } from '../types';
import { Input } from '@/components/ui/input';

export function UserSearch() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchEntry[]>([]);
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

    if (query.length < 2) {
      setResults([]);
      return;
    }

    debounceRef.current = setTimeout(async () => {
      setIsLoading(true);
      try {
        const response = await api.searchUsers(query);
        if (response.success && response.entries) {
          setResults(response.entries);
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
  }, [query]);

  const handleSelect = (entry: SearchEntry) => {
    const username =
      entry.attributes.sAMAccountName?.[0] ||
      entry.attributes.cn?.[0] ||
      entry.dn;
    navigate(`/user/${username}`);
    setQuery('');
    setIsOpen(false);
    setResults([]);
  };

  return (
    <div className="relative w-full max-w-[500px]" ref={wrapperRef}>
      <div className="relative flex items-center">
        <Search className="absolute left-4 w-5 h-5 text-muted-foreground pointer-events-none" />
        <Input
          type="text"
          placeholder="Search users by name or email..."
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
          {results.map((entry, index) => {
            const initials =
              (entry.attributes.givenName?.[0]?.charAt(0) || '') +
              (entry.attributes.sn?.[0]?.charAt(0) || '');

            return (
              <button
                key={index}
                className="flex items-center gap-3 px-4 py-3 w-full text-left hover:bg-muted transition-colors border-b border-border last:border-0"
                onClick={() => handleSelect(entry)}
              >
                <div className="w-10 h-10 rounded-full bg-primary flex items-center justify-center text-primary-foreground font-semibold text-sm uppercase shrink-0">
                  {initials}
                </div>
                <div className="flex-1 flex flex-col overflow-hidden">
                  <span className="text-sm font-medium text-foreground truncate">
                    {entry.attributes.displayName?.[0] || entry.attributes.cn?.[0] || 'Unknown'}
                  </span>
                  <span className="text-xs text-muted-foreground truncate">
                    {entry.attributes.mail?.[0] || 'No email'}
                  </span>
                </div>
                <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded font-mono shrink-0">
                  {entry.attributes.sAMAccountName?.[0]}
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
