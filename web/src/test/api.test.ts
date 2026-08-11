import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { api } from '../services/api';

vi.mock('axios', async (importOriginal) => {
  const actual = await importOriginal<typeof import('axios')>();
  return {
    default: {
      ...actual.default,
      create: vi.fn(() => ({
        interceptors: {
          request: { use: vi.fn() },
        },
        post: vi.fn(),
        get: vi.fn(),
      })),
      isAxiosError: actual.default.isAxiosError,
    },
  };
});

describe('ApiService', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('setSessionId / getSessionId', () => {
    it('stores a session ID in localStorage', () => {
      api.setSessionId('test-session');
      expect(localStorage.getItem('sessionId')).toBe('test-session');
      expect(api.getSessionId()).toBe('test-session');
    });

    it('removes session ID from localStorage when set to null', () => {
      localStorage.setItem('sessionId', 'old-session');
      api.setSessionId(null);
      expect(localStorage.getItem('sessionId')).toBeNull();
      expect(api.getSessionId()).toBeNull();
    });
  });

  describe('login', () => {
    it('returns success and stores session ID on successful login', async () => {
      const mockResponse = {
        data: { success: true, sessionId: 'sess-123', user: { sAMAccountName: 'alice', dn: 'cn=alice', enabled: true } },
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.post.mockResolvedValueOnce(mockResponse);

      const result = await api.login({ username: 'alice', password: 'pw' });

      expect(result.success).toBe(true);
      expect(api.getSessionId()).toBe('sess-123');
    });

    it('returns failure with status on HTTP error response', async () => {
      const axiosError = Object.assign(new Error('Unauthorized'), {
        isAxiosError: true,
        response: { status: 401, data: { success: false, message: 'Bad credentials' } },
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.post.mockRejectedValueOnce(axiosError);
      vi.spyOn(axios, 'isAxiosError').mockReturnValueOnce(true);

      const result = await api.login({ username: 'bob', password: 'wrong' });

      expect(result.success).toBe(false);
      expect(result.status).toBe(401);
    });

    it('returns a network error message when request fails without response', async () => {
      const networkError = new Error('Network Error');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.post.mockRejectedValueOnce(networkError);
      vi.spyOn(axios, 'isAxiosError').mockReturnValueOnce(false);

      const result = await api.login({ username: 'bob', password: 'pw' });

      expect(result.success).toBe(false);
      expect(result.message).toMatch(/network error/i);
    });
  });

  describe('healthCheck', () => {
    it('returns true when backend reports healthy', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockResolvedValueOnce({ data: { status: 'healthy' } });
      expect(await api.healthCheck()).toBe(true);
    });

    it('returns false when request fails', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockRejectedValueOnce(new Error('timeout'));
      expect(await api.healthCheck()).toBe(false);
    });
  });

  describe('getGroup', () => {
    it('requests the group endpoint and returns the group with its members', async () => {
      const mockResponse = {
        data: {
          success: true,
          group: { dn: 'CN=Admins,DC=example,DC=com', cn: 'Admins', sAMAccountName: 'Admins' },
          members: [{ dn: 'CN=Ann,DC=example,DC=com', cn: 'Ann', sAMAccountName: 'ann' }],
          memberCount: 1,
        },
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockResolvedValueOnce(mockResponse);

      const result = await api.getGroup('Admins');

      expect(result.success).toBe(true);
      expect(result.members).toHaveLength(1);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((api as any).client.get).toHaveBeenCalledWith('/api/v1/groups/Admins');
    });

    // Group names routinely contain spaces and slashes, which must not break the path.
    it('encodes the group name into the URL', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockResolvedValueOnce({
        data: { success: true, memberCount: 0 },
      });

      await api.getGroup('Domain Admins/EU');

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((api as any).client.get).toHaveBeenCalledWith(
        '/api/v1/groups/Domain%20Admins%2FEU'
      );
    });

    // The server's message (not found, not permitted) is what the page renders, so an
    // error response must come back as data rather than throwing.
    it('returns the error payload on an HTTP error response', async () => {
      const axiosError = Object.assign(new Error('Forbidden'), {
        isAxiosError: true,
        response: {
          status: 403,
          data: { success: false, memberCount: 0, error: 'Search is not permitted for this user' },
        },
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockRejectedValueOnce(axiosError);
      vi.spyOn(axios, 'isAxiosError').mockReturnValueOnce(true);

      const result = await api.getGroup('Admins');

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/not permitted/i);
    });

    it('returns an error result when the request fails without a response', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockRejectedValueOnce(new Error('Network Error'));
      vi.spyOn(axios, 'isAxiosError').mockReturnValueOnce(false);

      const result = await api.getGroup('Admins');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Network Error');
    });
  });

  describe('getVersion', () => {
    it('returns the version reported by the backend', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockResolvedValueOnce({
        data: { status: 'healthy', version: '1.4.0' },
      });
      expect(await api.getVersion()).toBe('1.4.0');
    });

    it('returns null when the backend omits a version', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockResolvedValueOnce({ data: { status: 'healthy' } });
      expect(await api.getVersion()).toBeNull();
    });

    it('returns null when request fails', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (api as any).client.get.mockRejectedValueOnce(new Error('timeout'));
      expect(await api.getVersion()).toBeNull();
    });
  });
});
