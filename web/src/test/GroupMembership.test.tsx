import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { GroupMembership } from '../components/GroupMembership';
import type { User } from '../types';
import api from '../services/api';

vi.mock('../services/api', () => ({
  default: {
    resolveGroups: vi.fn(),
    searchGroups: vi.fn(),
    addUserToGroup: vi.fn(),
    removeUserFromGroup: vi.fn(),
  },
}));

vi.mock('../contexts/NotificationContext', () => ({
  useNotification: () => ({ showNotification: vi.fn() }),
}));

// canSearch drives whether the debounced group-search effect runs at all. The render
// loop this suite guards against only occurs with it enabled, so it is switchable.
let canSearch = true;

vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => ({ canSearch }),
}));

const DIRECT_DN = 'CN=Engineering,OU=Groups,DC=example,DC=com';
const NESTED_DN = 'CN=All Staff,OU=Groups,DC=example,DC=com';

const user: User = {
  dn: 'CN=Test User,OU=Users,DC=example,DC=com',
  sAMAccountName: 'testuser',
  enabled: true,
  memberOf: [DIRECT_DN],
};

describe('GroupMembership nested toggle', () => {
  beforeEach(() => {
    canSearch = true;
    vi.mocked(api.searchGroups).mockResolvedValue({ success: true, count: 0, groups: [] });
    vi.mocked(api.resolveGroups).mockResolvedValue({
      success: true,
      count: 2,
      groups: [
        {
          dn: DIRECT_DN,
          cn: 'Engineering',
          sAMAccountName: 'Engineering',
          description: 'Engineers',
        },
        {
          dn: NESTED_DN,
          cn: 'All Staff',
          sAMAccountName: 'All Staff',
          description: 'Everyone',
          nested: true,
        },
      ],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows only direct groups by default', async () => {
    render(<GroupMembership user={user} />);

    // Wait for the resolve call to settle before asserting on absence, otherwise the
    // nested row is merely late rather than filtered out.
    await screen.findByRole('button', { name: /^All \(/ });

    expect(screen.getByText('Engineering')).toBeInTheDocument();
    expect(screen.queryByText('All Staff')).not.toBeInTheDocument();
  });

  it('renders nested groups after switching to All without crashing', async () => {
    render(<GroupMembership user={user} />);

    const allButton = await screen.findByRole('button', { name: /^All \(/ });
    fireEvent.click(allButton);

    await waitFor(() => {
      expect(screen.getByText('All Staff')).toBeInTheDocument();
    });
    expect(screen.getByText('Engineering')).toBeInTheDocument();
  });

  // Regression: passing a freshly filtered array as useReactTable's `data` (or a new
  // `columns` array) made the table rebuild and re-render in an unbounded loop, which
  // hung the tab with RESULT_CODE_HUNG. A settled component should be quiet, so any
  // sustained DOM churn while idle means the loop is back.
  it('settles instead of re-rendering forever once loaded', async () => {
    const { container } = render(<GroupMembership user={user} />);

    fireEvent.click(await screen.findByRole('button', { name: /^All \(/ }));
    await waitFor(() => {
      expect(screen.getByText('All Staff')).toBeInTheDocument();
    });

    let mutations = 0;
    const observer = new MutationObserver((records) => {
      mutations += records.length;
    });
    observer.observe(container, {
      childList: true,
      subtree: true,
      attributes: true,
      characterData: true,
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    observer.disconnect();

    // A quiet component produces no mutations; the looping version produced hundreds.
    expect(mutations).toBeLessThan(20);
  });
});
