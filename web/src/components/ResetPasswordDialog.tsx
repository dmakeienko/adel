import { useCallback, useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import { api } from '../services/api';
import { useNotification } from '../contexts/NotificationContext';
import { PasswordInput } from './PasswordInput';
import { PasswordRequirements } from './PasswordRequirements';
import { isPasswordComplex, validatePassword } from '../lib/password';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';

interface ResetPasswordDialogProps {
  open: boolean;
  targetUsername: string;
  onClose: () => void;
  onReset: () => void;
}

export function ResetPasswordDialog({
  open,
  targetUsername,
  onClose,
  onReset,
}: ResetPasswordDialogProps) {
  const { showNotification } = useNotification();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const validation = useMemo(() => validatePassword(newPassword), [newPassword]);
  const passwordsMatch = newPassword === confirmPassword;
  const isFormValid = newPassword.length > 0 && confirmPassword.length > 0 &&
    passwordsMatch && isPasswordComplex(validation);

  const resetAndClose = useCallback(() => {
    setNewPassword('');
    setConfirmPassword('');
    setIsSubmitting(false);
    onClose();
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isSubmitting) resetAndClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSubmitting, open, resetAndClose]);

  if (!open) return null;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!isFormValid || isSubmitting) return;

    setIsSubmitting(true);
    const result = await api.resetPassword(targetUsername, newPassword);
    setIsSubmitting(false);

    if (result.success) {
      showNotification(`Password reset for ${targetUsername}.`, 'success');
      onReset();
      resetAndClose();
    } else {
      showNotification(result.error || result.message || 'Failed to reset password.', 'error');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onMouseDown={(event) => {
      if (event.target === event.currentTarget && !isSubmitting) resetAndClose();
    }}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="reset-password-title"
        className="w-full max-w-lg rounded-xl border border-border bg-card p-6 shadow-xl"
      >
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 id="reset-password-title" className="text-xl font-semibold text-foreground">Reset password</h2>
            <p className="mt-1 text-sm text-muted-foreground">Set a new password for {targetUsername}.</p>
          </div>
          <button
            type="button"
            aria-label="Close reset password dialog"
            className="text-muted-foreground transition-colors hover:text-foreground"
            onClick={resetAndClose}
            disabled={isSubmitting}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <form className="space-y-5" onSubmit={handleSubmit}>
          <div className="space-y-2">
            <Label htmlFor="resetNewPassword">New password</Label>
            <PasswordInput id="resetNewPassword" value={newPassword} onChange={setNewPassword} autoFocus />
          </div>

          {newPassword.length > 0 && <PasswordRequirements validation={validation} />}

          <div className="space-y-2">
            <Label htmlFor="resetConfirmPassword">Confirm password</Label>
            <PasswordInput id="resetConfirmPassword" value={confirmPassword} onChange={setConfirmPassword} />
            {confirmPassword.length > 0 && !passwordsMatch && (
              <p className="text-sm text-destructive">Passwords do not match</p>
            )}
          </div>

          <div className="flex justify-end gap-3 pt-1">
            <Button type="button" variant="outline" onClick={resetAndClose} disabled={isSubmitting}>Cancel</Button>
            <Button type="submit" disabled={!isFormValid || isSubmitting}>
              {isSubmitting ? 'Resetting...' : 'Confirm'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
