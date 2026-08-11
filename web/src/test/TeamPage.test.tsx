import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { TeamPage } from '../pages/TeamPage';
import type { TeamResponse } from '../types';
import api from '../services/api';

vi.mock('../services/api', () => ({
  default: { getTeam: vi.fn(), getVersion: vi.fn().mockResolvedValue(null) },
}));

// The sidebar is rendered by the page but is not what these tests exercise.
vi.mock('../components/Sidebar', () => ({ Sidebar: () => null }));

let auth = {
  isAuthenticated: true,
  isLoading: false,
  isLead: true,
  leadGroups: ['CN=engineering-*'],
};

vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => auth,
}));

const teamResponse: TeamResponse = {
  success: true,
  memberCount: 2,
  lead_group_membership: ['CN=engineering-*'],
  groups: [
    {
      group: {
        dn: 'CN=engineering,OU=Groups,DC=example,DC=com',
        cn: 'engineering',
        sAMAccountName: 'engineering',
      },
      members: [
        {
          dn: 'CN=Ann Lee,OU=Users,DC=example,DC=com',
          cn: 'Ann Lee',
          sAMAccountName: 'alee',
          displayName: 'Ann Lee',
          mail: 'alee@example.com',
        },
        {
          dn: 'CN=Bob Roy,OU=Users,DC=example,DC=com',
          cn: 'Bob Roy',
          sAMAccountName: 'broy',
          displayName: 'Bob Roy',
          mail: 'broy@example.com',
        },
      ],
    },
  ],
};

const renderPage = () =>
  render(
    <MemoryRouter>
      <TeamPage />
    </MemoryRouter>
  );

describe('TeamPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth = {
      isAuthenticated: true,
      isLoading: false,
      isLead: true,
      leadGroups: ['CN=engineering-*'],
    };
  });

  it('lists the members of each group the user leads', async () => {
    vi.mocked(api.getTeam).mockResolvedValue(teamResponse);

    renderPage();

    expect(await screen.findByText('Ann Lee')).toBeInTheDocument();
    expect(screen.getByText('Bob Roy')).toBeInTheDocument();
    expect(screen.getByText('engineering')).toBeInTheDocument();
    // The distinct headcount comes from the server, not the row count.
    expect(screen.getByText('2 people')).toBeInTheDocument();
  });

  it('filters members by name without refetching', async () => {
    vi.mocked(api.getTeam).mockResolvedValue(teamResponse);

    renderPage();
    await screen.findByText('Ann Lee');

    fireEvent.change(screen.getByLabelText('Filter team members'), {
      target: { value: 'bob' },
    });

    await waitFor(() => {
      expect(screen.queryByText('Ann Lee')).not.toBeInTheDocument();
    });
    expect(screen.getByText('Bob Roy')).toBeInTheDocument();
    // Filtering is client-side over an already-scoped list.
    expect(api.getTeam).toHaveBeenCalledTimes(1);
  });

  it('tells a non-lead there is no team rather than calling the API', async () => {
    auth = { ...auth, isLead: false, leadGroups: [] };

    renderPage();

    expect(await screen.findByText('Not available')).toBeInTheDocument();
    expect(api.getTeam).not.toHaveBeenCalled();
  });

  it('surfaces a server error', async () => {
    vi.mocked(api.getTeam).mockResolvedValue({
      success: false,
      memberCount: 0,
      error: 'Failed to resolve team',
    });

    renderPage();

    expect(await screen.findByText('Failed to resolve team')).toBeInTheDocument();
  });
});
