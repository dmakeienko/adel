import { useState, useMemo } from 'react';
import { Navigate } from 'react-router-dom';
import { Eye, EyeOff, CheckCircle2, XCircle } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useNotification } from '../contexts/NotificationContext';
import { Sidebar } from '../components/Sidebar';
import { api } from '../services/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';

interface PasswordValidation {
  minLength: boolean;
  hasNumber: boolean;
  hasCapital: boolean;
  hasSpecial: boolean;
  isDifferentFromOld: boolean;
}

export function ChangePasswordPage() {
  const { user, isAuthenticated, isLoading } = useAuth();
  const { showNotification } = useNotification();
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const showValidation = newPassword.length > 0;

  const validation = useMemo<PasswordValidation>(() => {
    if (!newPassword) {
      return { minLength: false, hasNumber: false, hasCapital: false, hasSpecial: false, isDifferentFromOld: true };
    }
    return {
      minLength: newPassword.length >= 9,
      hasNumber: /\d/.test(newPassword),
      hasCapital: /[A-Z]/.test(newPassword),
      hasSpecial: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(newPassword),
      isDifferentFromOld: oldPassword === '' || newPassword !== oldPassword,
    };
  }, [newPassword, oldPassword]);

  const isPasswordValid = () =>
    validation.minLength && validation.hasNumber && validation.hasCapital &&
    validation.hasSpecial && validation.isDifferentFromOld;

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
                    show={showOldPassword}
                    onToggle={() => setShowOldPassword(!showOldPassword)}
                  />
                </div>

                {/* New password */}
                <div className="space-y-2">
                  <Label htmlFor="newPassword">New Password</Label>
                  <PasswordInput
                    id="newPassword"
                    value={newPassword}
                    onChange={setNewPassword}
                    show={showNewPassword}
                    onToggle={() => setShowNewPassword(!showNewPassword)}
                  />
                </div>

                {/* Requirements */}
                {showValidation && (
                  <div className="p-4 bg-muted rounded-lg border border-border space-y-2">
                    <p className="text-sm font-semibold text-foreground">Password must contain:</p>
                    <ul className="space-y-2">
                      <RequirementItem met={validation.minLength} label="At least 9 characters" />
                      <RequirementItem met={validation.hasNumber} label="At least one number" />
                      <RequirementItem met={validation.hasCapital} label="At least one capital letter" />
                      <RequirementItem met={validation.hasSpecial} label="At least one special character" />
                      <RequirementItem met={validation.isDifferentFromOld} label="Cannot match your current password" />
                      <RequirementItem met={validation.isDifferentFromOld} label="Cannot match any of your last 25 passwords" />
                    </ul>
                  </div>
                )}

                {/* Confirm password */}
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm New Password</Label>
                  <PasswordInput
                    id="confirmPassword"
                    value={confirmPassword}
                    onChange={setConfirmPassword}
                    show={showConfirmPassword}
                    onToggle={() => setShowConfirmPassword(!showConfirmPassword)}
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

function PasswordInput({
  id, value, onChange, show, onToggle,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  show: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="relative">
      <Input
        type={show ? 'text' : 'password'}
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required
        className="pr-11"
      />
      <button
        type="button"
        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
        onClick={onToggle}
        tabIndex={-1}
        aria-label={show ? 'Hide password' : 'Show password'}
      >
        {show ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
      </button>
    </div>
  );
}

function RequirementItem({ met, label }: { met: boolean; label: string }) {
  return (
    <li className={`flex items-center gap-2 text-sm transition-colors ${met ? 'text-green-600' : 'text-destructive'}`}>
      {met
        ? <CheckCircle2 className="w-4 h-4 shrink-0" />
        : <XCircle className="w-4 h-4 shrink-0" />}
      {label}
    </li>
  );
}
