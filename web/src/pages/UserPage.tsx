import { useState, useEffect, useCallback } from 'react';
import { useParams, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useNotification } from '../contexts/NotificationContext';
import { Sidebar } from '../components/Sidebar';
import { UserSearch } from '../components/UserSearch';
import { GroupMembership } from '../components/GroupMembership';
import type { User } from '../types';
import api from '../services/api';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';

export function UserPage() {
  const { username } = useParams<{ username: string }>();
  const { user: currentUser, isAuthenticated, isLoading } = useAuth();
  const { showNotification } = useNotification();
  const [user, setUser] = useState<User | null>(null);
  const [isLoadingUser, setIsLoadingUser] = useState(true);

  const loadUser = useCallback(async () => {
    if (!username) return;

    setIsLoadingUser(true);
    try {
      const response = await api.getUser(username);
      if (response.success && response.user) {
        setUser(response.user);
      } else {
        showNotification(response.error || 'User not found', 'error');
        setUser(null);
      }
    } catch {
      showNotification('Failed to load user data', 'error');
      setUser(null);
    } finally {
      setIsLoadingUser(false);
    }
  }, [username, showNotification]);

  useEffect(() => {
    if (isAuthenticated && username) {
      loadUser();
    }
  }, [username, isAuthenticated, loadUser]);

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

  const formatDate = (dateStr?: string | null): string => {
    if (!dateStr || dateStr === null) return '-';
    try {
      const date = new Date(dateStr);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return dateStr;
    }
  };

  const isViewingOwnProfile = currentUser?.sAMAccountName === username;
  const initials =
    (user?.givenName?.charAt(0) || user?.sAMAccountName.charAt(0) || '') +
    (user?.sn?.charAt(0) || '');

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar />

      <main className="flex-1 ml-64 flex flex-col h-screen overflow-hidden bg-background">
        {/* Header */}
        <header className="flex items-center justify-between px-8 py-5 bg-card border-b border-border shrink-0">
          <div className="flex items-center gap-8 flex-1">
            <h2 className="text-xl font-semibold text-foreground whitespace-nowrap">User</h2>
            <UserSearch />
          </div>
        </header>

        {isLoadingUser ? (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 text-muted-foreground">
            <div className="w-10 h-10 rounded-full border-3 border-muted border-t-primary animate-spin" />
            <p>Loading user data...</p>
          </div>
        ) : user ? (
          <div className="flex-1 overflow-y-auto p-8 flex flex-col gap-6">
            {/* Profile card */}
            <Card>
              <CardHeader className="pb-0">
                <CardTitle className="text-lg">Profile</CardTitle>
              </CardHeader>
              <CardContent className="pt-5">
                {/* Avatar + summary */}
                <div className="flex items-start gap-5 pb-6">
                  <Avatar className="w-20 h-20 text-3xl shrink-0">
                    <AvatarFallback className="font-semibold uppercase">
                      {initials}
                    </AvatarFallback>
                  </Avatar>

                  <div className="flex flex-col justify-between self-stretch">
                    <div className="flex flex-col gap-1">
                      <h3 className="text-2xl font-semibold text-foreground">
                        {user.displayName || user.sAMAccountName}
                      </h3>
                      <p className="text-sm text-muted-foreground">{user.title || 'No title'}</p>
                    </div>
                    {!isViewingOwnProfile && (
                      <Badge variant="outline" className="self-start bg-amber-50 text-amber-800 border-amber-200">
                        Viewing another user's profile
                      </Badge>
                    )}
                  </div>
                </div>

                <Separator className="mb-6" />

                {/* Profile grid */}
                <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-5">
                  <div className="flex flex-col gap-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Status</label>
                    <div>
                      <Badge variant={user.enabled ? 'success' : 'warning'}>
                        {user.enabled ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                  </div>
                  <ProfileField label="Username" value={user.sAMAccountName} />
                  <div className="flex flex-col gap-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Email</label>
                    <span className="text-sm text-foreground">
                      {user.mail ? <a href={`mailto:${user.mail}`}>{user.mail}</a> : '-'}
                    </span>
                  </div>
                  <ProfileField label="Account Exp. Date" value={user.accountExpires === null ? 'Never' : formatDate(user.accountExpires)} />

                  <ProfileField label="Name" value={user.givenName} />
                  <ProfileField label="Last Name" value={user.sn} />
                  <ProfileField label="Full Name" value={user.displayName} />

                  <div className="col-span-full flex flex-col gap-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">DN</label>
                    <span className="font-mono text-sm text-muted-foreground bg-muted px-3 py-2 rounded-md break-all">
                      {user.dn}
                    </span>
                  </div>

                  <ProfileField label="Password Last Set" value={user.pwdLastSet === null ? 'Not Set' : formatDate(user.pwdLastSet)} />
                  <ProfileField label="Password Exp. Date" value={user.passwordExpiryDate === null ? 'Never' : formatDate(user.passwordExpiryDate)} />
                </div>
              </CardContent>
            </Card>

            <GroupMembership user={user} onUpdate={loadUser} />
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <h3 className="text-xl font-semibold text-foreground mb-2">User not found</h3>
            <p className="text-sm text-muted-foreground">
              The user "{username}" could not be found in Active Directory.
            </p>
          </div>
        )}
      </main>
    </div>
  );
}

function ProfileField({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">{label}</label>
      <span className="text-sm text-foreground">{value || '-'}</span>
    </div>
  );
}
