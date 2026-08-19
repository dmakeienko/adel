import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { UserPage } from '../pages/UserPage';
import api from '../services/api';

vi.mock('../services/api', () => ({
  default: { getUser: vi.fn() },
}));
vi.mock('../components/Sidebar', () => ({ Sidebar: () => null }));
vi.mock('../components/UserSearch', () => ({ UserSearch: () => null }));
vi.mock('../components/GroupMembership', () => ({ GroupMembership: () => null }));
vi.mock('../contexts/NotificationContext', () => ({
  useNotification: () => ({ showNotification: vi.fn() }),
}));

let auth = {
  user: { dn: 'CN=Admin,DC=example,DC=com', sAMAccountName: 'admin', enabled: true },
  isAuthenticated: true,
  isLoading: false,
  canResetPassword: true,
};

vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => auth,
}));

const target = {
  dn: 'CN=Alice,DC=example,DC=com',
  sAMAccountName: 'alice',
  displayName: 'Alice Example',
  enabled: true,
  pwdLastSet: null,
  passwordExpiryDate: null,
  accountExpires: null,
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/users/alice']}>
      <Routes>
        <Route path="/users/:username" element={<UserPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('UserPage password reset capability', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth = { ...auth, canResetPassword: true };
    vi.mocked(api.getUser).mockResolvedValue({ success: true, user: target });
  });

  it('shows the reset button when the session has permission', async () => {
    renderPage();
    expect(await screen.findByRole('button', { name: 'Reset password' })).toBeInTheDocument();
  });

  it('hides the reset button when the session lacks permission', async () => {
    auth = { ...auth, canResetPassword: false };
    renderPage();
    await screen.findByRole('heading', { name: 'Alice Example' });
    expect(screen.queryByRole('button', { name: 'Reset password' })).not.toBeInTheDocument();
  });
});
