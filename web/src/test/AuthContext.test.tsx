import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AxiosError, AxiosHeaders } from 'axios';
import { AuthProvider, useAuth } from '../contexts/AuthContext';
import api from '../services/api';

vi.mock('../services/api', () => ({
  default: {
    getSessionId: vi.fn(),
    setSessionId: vi.fn(),
    getCurrentUser: vi.fn(),
    getSessionInfo: vi.fn(),
  },
}));

function httpError(status: number): AxiosError {
  const config = { headers: new AxiosHeaders() };
  return new AxiosError('request failed', String(status), config, null, {
    status,
    statusText: '',
    headers: {},
    config,
    data: {},
  });
}

function Probe() {
  const { isLoading, isAuthenticated } = useAuth();
  return <div>{isLoading ? 'loading' : isAuthenticated ? 'in' : 'out'}</div>;
}

describe('AuthProvider session restore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getSessionId).mockReturnValue('stored-session');
  });

  it('clears the stored session when the server answers 401', async () => {
    vi.mocked(api.getCurrentUser).mockRejectedValue(httpError(401));
    render(<AuthProvider><Probe /></AuthProvider>);

    await waitFor(() => expect(screen.getByText('out')).toBeInTheDocument());
    expect(api.setSessionId).toHaveBeenCalledWith(null);
  });

  it.each([500, 502, 503])('keeps the stored session on a %i', async (status) => {
    vi.mocked(api.getCurrentUser).mockRejectedValue(httpError(status));
    render(<AuthProvider><Probe /></AuthProvider>);

    await waitFor(() => expect(screen.getByText('out')).toBeInTheDocument());
    expect(api.setSessionId).not.toHaveBeenCalled();
  });

  it('keeps the stored session on a network error', async () => {
    vi.mocked(api.getCurrentUser).mockRejectedValue(new AxiosError('Network Error', 'ERR_NETWORK'));
    render(<AuthProvider><Probe /></AuthProvider>);

    await waitFor(() => expect(screen.getByText('out')).toBeInTheDocument());
    expect(api.setSessionId).not.toHaveBeenCalled();
  });
});
