import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ResetPasswordDialog } from '../components/ResetPasswordDialog';
import { api } from '../services/api';

const showNotification = vi.fn();

vi.mock('../services/api', () => {
  const mockedApi = { resetPassword: vi.fn() };
  return { api: mockedApi, default: mockedApi };
});

vi.mock('../contexts/NotificationContext', () => ({
  useNotification: () => ({ showNotification }),
}));

describe('ResetPasswordDialog', () => {
  const onClose = vi.fn();
  const onReset = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('cancels without making a reset request', () => {
    render(
      <ResetPasswordDialog
        open
        targetUsername="alice"
        onClose={onClose}
        onReset={onReset}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(api.resetPassword).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('requires matching passwords that satisfy the shared complexity rules', () => {
    render(
      <ResetPasswordDialog
        open
        targetUsername="alice"
        onClose={onClose}
        onReset={onReset}
      />
    );

    const confirm = screen.getByRole('button', { name: 'Confirm' });
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'simple' } });
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'simple' } });

    expect(confirm).toBeDisabled();
    expect(screen.getByText('At least 9 characters')).toBeInTheDocument();
  });

  it('resets the target and closes after a successful confirmation', async () => {
    vi.mocked(api.resetPassword).mockResolvedValue({ success: true });
    render(
      <ResetPasswordDialog
        open
        targetUsername="alice"
        onClose={onClose}
        onReset={onReset}
      />
    );

    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Secure123!' } });
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Secure123!' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    await waitFor(() => expect(api.resetPassword).toHaveBeenCalledWith('alice', 'Secure123!'));
    expect(onReset).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledOnce();
    expect(showNotification).toHaveBeenCalledWith('Password reset for alice.', 'success');
  });
});
