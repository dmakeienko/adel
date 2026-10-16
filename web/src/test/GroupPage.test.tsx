import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { GroupPage } from '../pages/GroupPage';
import api from '../services/api';
import type { GroupDetailResponse } from '../types';

vi.mock('../services/api', () => ({
  default: {
    getGroup: vi.fn(),
    searchUsers: vi.fn(),
    searchGroups: vi.fn(),
    addMemberGroup: vi.fn(),
    addGroupMember: vi.fn(),
    removeGroupMember: vi.fn(),
    removeMemberGroup: vi.fn(),
  },
}));
vi.mock('../components/Sidebar', () => ({ Sidebar: () => null }));
vi.mock('../components/GroupSearch', () => ({ GroupSearch: () => null }));

const showNotification = vi.fn();
vi.mock('../contexts/NotificationContext', () => ({
  useNotification: () => ({ showNotification }),
}));

let auth = {
  isAuthenticated: true,
  isLoading: false,
  canSearch: true,
  canManageGroupMembers: true,
};
vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => auth,
}));

const groupResponse: GroupDetailResponse = {
  success: true,
  memberCount: 2,
  group: {
    dn: 'CN=Staff,OU=Groups,DC=example,DC=com',
    cn: 'Staff',
    sAMAccountName: 'Staff',
  },
  members: [
    {
      dn: 'CN=Ann Lee,OU=Users,DC=example,DC=com',
      cn: 'Ann Lee',
      sAMAccountName: 'alee',
      displayName: 'Ann Lee',
    },
    {
      dn: 'CN=Sub,OU=Groups,DC=example,DC=com',
      cn: 'Sub',
      sAMAccountName: 'Sub',
      isGroup: true,
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/group/Staff']}>
      <Routes>
        <Route path="/group/:groupName" element={<GroupPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('GroupPage member management', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth = { ...auth, canSearch: true, canManageGroupMembers: true };
    vi.mocked(api.getGroup).mockResolvedValue(groupResponse);
  });

  it('shows the add box and remove controls when the session has permission', async () => {
    renderPage();

    expect(await screen.findByLabelText('Add a member')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove Ann Lee' })).toBeInTheDocument();
  });

  it('hides every management control when the session lacks permission', async () => {
    auth = { ...auth, canManageGroupMembers: false };
    renderPage();

    await screen.findByText('Members (2)');
    expect(screen.queryByLabelText('Add a member')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Remove/ })).not.toBeInTheDocument();
    expect(screen.queryByText('Actions')).not.toBeInTheDocument();
  });

  it('offers a remove button for users and nested groups alike', async () => {
    renderPage();

    await screen.findByText('Members (2)');
    expect(screen.getByRole('button', { name: 'Remove Ann Lee' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove Sub' })).toBeInTheDocument();
  });

  it('removes a nested group through the group endpoint, not the user one', async () => {
    const user = userEvent.setup();
    vi.mocked(api.removeMemberGroup).mockResolvedValue({ success: true });
    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Remove Sub' }));
    expect(api.removeMemberGroup).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Confirm removing Sub' }));

    await waitFor(() => expect(api.removeMemberGroup).toHaveBeenCalledWith('Staff', 'Sub'));
    expect(api.removeGroupMember).not.toHaveBeenCalled();
    await waitFor(() => expect(api.getGroup).toHaveBeenCalledTimes(2));
    expect(showNotification).toHaveBeenCalledWith('Group Sub removed from Staff.', 'success');
  });

  it('shows the server error when removing a nested group fails', async () => {
    const user = userEvent.setup();
    vi.mocked(api.removeMemberGroup).mockResolvedValue({
      success: false,
      error: 'Group is not a member of this group',
    });
    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Remove Sub' }));
    await user.click(screen.getByRole('button', { name: 'Confirm removing Sub' }));

    await waitFor(() =>
      expect(showNotification).toHaveBeenCalledWith('Group is not a member of this group', 'error')
    );
    expect(api.getGroup).toHaveBeenCalledTimes(1);
  });

  it('confirms one row at a time, so a pending confirmation never spans two members', async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Remove Sub' }));

    expect(screen.getByRole('button', { name: 'Confirm removing Sub' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm removing Ann Lee' })).not.toBeInTheDocument();
  });

  it('requires confirmation before removing, and cancel makes no request', async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Remove Ann Lee' }));
    expect(api.removeGroupMember).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(api.removeGroupMember).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Remove Ann Lee' })).toBeInTheDocument();
  });

  it('removes a confirmed member and reloads the list', async () => {
    const user = userEvent.setup();
    vi.mocked(api.removeGroupMember).mockResolvedValue({ success: true });
    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Remove Ann Lee' }));
    await user.click(screen.getByRole('button', { name: 'Confirm removing Ann Lee' }));

    await waitFor(() => expect(api.removeGroupMember).toHaveBeenCalledWith('Staff', 'alee'));
    await waitFor(() => expect(api.getGroup).toHaveBeenCalledTimes(2));
    expect(showNotification).toHaveBeenCalledWith('alee removed from Staff.', 'success');
  });

  it('surfaces the server error when removal fails and does not reload', async () => {
    const user = userEvent.setup();
    vi.mocked(api.removeGroupMember).mockResolvedValue({
      success: false,
      error: 'Permission denied: You don\'t have rights to modify this group',
    });
    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Remove Ann Lee' }));
    await user.click(screen.getByRole('button', { name: 'Confirm removing Ann Lee' }));

    await waitFor(() =>
      expect(showNotification).toHaveBeenCalledWith(
        'Permission denied: You don\'t have rights to modify this group',
        'error'
      )
    );
    expect(api.getGroup).toHaveBeenCalledTimes(1);
  });

  it('adds a user found by search and reloads the list', async () => {
    const user = userEvent.setup();
    vi.mocked(api.searchUsers).mockResolvedValue({
      success: true,
      count: 2,
      entries: [
        {
          dn: 'CN=Bob Roy,OU=Users,DC=example,DC=com',
          attributes: { sAMAccountName: ['broy'], displayName: ['Bob Roy'], mail: ['b@example.com'] },
        },
        {
          dn: 'CN=Ann Lee,OU=Users,DC=example,DC=com',
          attributes: { sAMAccountName: ['alee'], displayName: ['Ann Lee'] },
        },
      ],
    });
    vi.mocked(api.addGroupMember).mockResolvedValue({ success: true });
    renderPage();

    await user.type(await screen.findByLabelText('Add a member'), 'bo');
    const option = await screen.findByRole('button', { name: /^Bob Roy/ }, { timeout: 2000 });

    // Someone already in the group is listed but cannot be picked again.
    expect(screen.getByRole('button', { name: /^Ann Lee/ })).toBeDisabled();

    await user.click(option);

    await waitFor(() => expect(api.addGroupMember).toHaveBeenCalledWith('Staff', 'broy'));
    await waitFor(() => expect(api.getGroup).toHaveBeenCalledTimes(2));
    expect(showNotification).toHaveBeenCalledWith('Bob Roy added to Staff.', 'success');
  });

  it('shows the server error when adding fails', async () => {
    const user = userEvent.setup();
    vi.mocked(api.searchUsers).mockResolvedValue({
      success: true,
      count: 1,
      entries: [
        {
          dn: 'CN=Bob Roy,OU=Users,DC=example,DC=com',
          attributes: { sAMAccountName: ['broy'], displayName: ['Bob Roy'] },
        },
      ],
    });
    vi.mocked(api.addGroupMember).mockResolvedValue({
      success: false,
      error: 'User is already a member of this group',
    });
    renderPage();

    await user.type(await screen.findByLabelText('Add a member'), 'bo');
    await user.click(await screen.findByRole('button', { name: /^Bob Roy/ }, { timeout: 2000 }));

    await waitFor(() =>
      expect(showNotification).toHaveBeenCalledWith('User is already a member of this group', 'error')
    );
    expect(api.getGroup).toHaveBeenCalledTimes(1);
    // The table is still there, untouched.
    expect(within(screen.getByRole('table')).getByText('Ann Lee')).toBeInTheDocument();
  });

  describe('adding a group', () => {
    const groups = [
      { dn: 'CN=Contractors,OU=Groups,DC=example,DC=com', cn: 'Contractors', sAMAccountName: 'Contractors', description: 'External staff' },
      { dn: 'CN=Sub,OU=Groups,DC=example,DC=com', cn: 'Sub', sAMAccountName: 'Sub' },
      { dn: 'CN=Staff,OU=Groups,DC=example,DC=com', cn: 'Staff', sAMAccountName: 'Staff' },
    ];

    async function openGroupSearch(user: ReturnType<typeof userEvent.setup>, text: string) {
      await user.click(await screen.findByRole('button', { name: 'Search groups' }));
      await user.type(screen.getByLabelText('Add a group'), text);
    }

    it('starts in user mode and searches groups, not users, after switching', async () => {
      const user = userEvent.setup();
      vi.mocked(api.searchGroups).mockResolvedValue({ success: true, count: 1, groups: [groups[0]] });
      renderPage();

      const toggle = await screen.findByRole('button', { name: 'Search groups' });
      expect(toggle).toHaveAttribute('aria-pressed', 'false');
      expect(toggle).toHaveTextContent('Users');
      expect(screen.getByPlaceholderText('Add a member by name or email...')).toBeInTheDocument();

      await openGroupSearch(user, 'con');
      await screen.findByRole('button', { name: /^Contractors/ }, { timeout: 2000 });

      expect(api.searchGroups).toHaveBeenCalledWith('con');
      expect(api.searchUsers).not.toHaveBeenCalled();
    });

    it('toggles back and forth, changing the label and the search box text', async () => {
      const user = userEvent.setup();
      renderPage();

      const toggle = await screen.findByRole('button', { name: 'Search groups' });
      await user.click(toggle);

      expect(toggle).toHaveAttribute('aria-pressed', 'true');
      expect(toggle).toHaveTextContent('Groups');
      expect(screen.getByPlaceholderText('Add a group by name...')).toBeInTheDocument();
      expect(screen.getByLabelText('Add a group')).toBeInTheDocument();

      await user.click(toggle);

      expect(toggle).toHaveAttribute('aria-pressed', 'false');
      expect(screen.getByPlaceholderText('Add a member by name or email...')).toBeInTheDocument();
    });

    it('nests the chosen group and reloads the list', async () => {
      const user = userEvent.setup();
      vi.mocked(api.searchGroups).mockResolvedValue({ success: true, count: 1, groups: [groups[0]] });
      vi.mocked(api.addMemberGroup).mockResolvedValue({ success: true });
      renderPage();

      await openGroupSearch(user, 'con');
      await user.click(await screen.findByRole('button', { name: /^Contractors/ }, { timeout: 2000 }));

      await waitFor(() => expect(api.addMemberGroup).toHaveBeenCalledWith('Staff', 'Contractors'));
      expect(api.addGroupMember).not.toHaveBeenCalled();
      await waitFor(() => expect(api.getGroup).toHaveBeenCalledTimes(2));
      expect(showNotification).toHaveBeenCalledWith('Group Contractors added to Staff.', 'success');
    });

    it('does not offer the group itself or a group that is already a member', async () => {
      const user = userEvent.setup();
      vi.mocked(api.searchGroups).mockResolvedValue({ success: true, count: 3, groups });
      renderPage();

      await openGroupSearch(user, 'st');
      await screen.findByRole('button', { name: /^Contractors/ }, { timeout: 2000 });

      expect(screen.getByRole('button', { name: /^Contractors/ })).toBeEnabled();
      expect(screen.getByRole('button', { name: /^Sub/ })).toBeDisabled();
      expect(screen.getByRole('button', { name: /^Staff/ })).toBeDisabled();
    });

    it('shows the server error when nesting fails', async () => {
      const user = userEvent.setup();
      vi.mocked(api.searchGroups).mockResolvedValue({ success: true, count: 1, groups: [groups[0]] });
      vi.mocked(api.addMemberGroup).mockResolvedValue({
        success: false,
        error: 'Group is already a member of this group',
      });
      renderPage();

      await openGroupSearch(user, 'con');
      await user.click(await screen.findByRole('button', { name: /^Contractors/ }, { timeout: 2000 }));

      await waitFor(() =>
        expect(showNotification).toHaveBeenCalledWith('Group is already a member of this group', 'error')
      );
      expect(api.getGroup).toHaveBeenCalledTimes(1);
    });

    it('is not offered without the capability', async () => {
      auth = { ...auth, canManageGroupMembers: false };
      renderPage();

      await screen.findByText('Members (2)');
      expect(screen.queryByRole('button', { name: 'Search groups' })).not.toBeInTheDocument();
    });
  });
});
