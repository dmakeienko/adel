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
});
