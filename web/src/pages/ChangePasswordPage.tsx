import { useState, useMemo } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useNotification } from '../contexts/NotificationContext';
import { Sidebar } from '../components/Sidebar';
import { PasswordInput } from '../components/PasswordInput';
import { PasswordRequirements } from '../components/PasswordRequirements';
import { isPasswordComplex, validatePassword } from '../lib/password';
import { api } from '../services/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';

export function ChangePasswordPage() {
  const { user, isAuthenticated, isLoading } = useAuth();
  const { showNotification } = useNotification();
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const showValidation = newPassword.length > 0;

  const validation = useMemo(() => validatePassword(newPassword), [newPassword]);
  const isDifferentFromOld = oldPassword === '' || newPassword !== oldPassword;

  const isPasswordValid = () =>
    isPasswordComplex(validation) && isDifferentFromOld;

  const isFormValid = () =>
    oldPassword.trim() !== '' && newPassword.trim() !== '' &&
    confirmPassword.trim() !== '' && newPassword === confirmPassword && isPasswordValid();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isFormValid()) return;

    setIsSubmitting(true);
    const result = await api.changePassword(oldPassword, newPassword);
    setIsSubmitting(false);

    if (result.success) {
      showNotification('Password changed successfully.', 'success');
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } else {
      showNotification(result.error || result.message || 'Failed to change password.', 'error');
    }
  };

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
        <header className="flex items-center px-8 py-5 bg-card border-b border-border shrink-0">
          <h2 className="text-xl font-semibold text-foreground">Change Password</h2>
        </header>

        <div className="flex-1 overflow-y-auto flex items-center justify-center p-8">
          <Card className="w-full max-w-[600px]">
            <CardHeader>
              <CardTitle className="text-2xl">Change Your Password</CardTitle>
              <CardDescription>
                Enter your current password and choose a new secure password.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form className="space-y-6" onSubmit={handleSubmit}>
                {/* Username (read-only) */}
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    type="text"
                    id="username"
                    value={user?.sAMAccountName || ''}
                    disabled
                    className="bg-muted text-muted-foreground cursor-not-allowed"
                  />
                </div>

                {/* Old password */}
                <div className="space-y-2">
                  <Label htmlFor="oldPassword">Old Password</Label>
                  <PasswordInput
                    id="oldPassword"
                    value={oldPassword}
                    onChange={setOldPassword}
                    autoComplete="current-password"
                  />
                </div>

                {/* New password */}
                <div className="space-y-2">
                  <Label htmlFor="newPassword">New Password</Label>
                  <PasswordInput
                    id="newPassword"
                    value={newPassword}
                    onChange={setNewPassword}
                  />
                </div>

                {/* Requirements */}
                {showValidation && (
                  <PasswordRequirements
                    validation={validation}
                    additionalRequirements={[
                      { met: isDifferentFromOld, label: 'Cannot match your current password' },
                      { met: isDifferentFromOld, label: 'Cannot match any of your last 25 passwords' },
                    ]}
                  />
                )}

                {/* Confirm password */}
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm New Password</Label>
                  <PasswordInput
                    id="confirmPassword"
                    value={confirmPassword}
                    onChange={setConfirmPassword}
                  />
                  {confirmPassword && newPassword !== confirmPassword && (
                    <p className="text-sm text-destructive">Passwords do not match</p>
                  )}
                </div>

                <Button
                  type="submit"
                  disabled={!isFormValid() || isSubmitting}
                  className="w-full"
                >
                  {isSubmitting ? 'Changing...' : 'Confirm'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
