import axios, { type AxiosInstance } from 'axios';
import type {
  LoginRequest,
  LoginResponse,
  UserResponse,
  GroupsResponse,
  APIResponse,
  SearchResponse,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

class ApiService {
  private client: AxiosInstance;
  private sessionId: string | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.client.interceptors.request.use((config) => {
      if (this.sessionId) {
        config.headers['X-Session-ID'] = this.sessionId;
      }
      return config;
    });

    const storedSessionId = localStorage.getItem('sessionId');
    if (storedSessionId) {
      this.sessionId = storedSessionId;
    }
  }

  setSessionId(sessionId: string | null) {
    this.sessionId = sessionId;
    if (sessionId) {
      localStorage.setItem('sessionId', sessionId);
    } else {
      localStorage.removeItem('sessionId');
    }
  }

  getSessionId(): string | null {
    return this.sessionId;
  }

  async login(credentials: LoginRequest): Promise<LoginResponse & { status?: number }> {
    try {
      const response = await this.client.post<LoginResponse>(
        '/api/v1/login',
        credentials
      );
      if (response.data.success && response.data.sessionId) {
        this.setSessionId(response.data.sessionId);
      }
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response) {
        return { ...(error.response.data as LoginResponse), status: error.response.status };
      }
      return { success: false, message: 'Network error, please try again' };
    }
  }

  async logout(): Promise<APIResponse> {
    const response = await this.client.post<APIResponse>('/api/v1/logout', {
      sessionId: this.sessionId,
    });
    this.setSessionId(null);
    return response.data;
  }

  async getCurrentUser(): Promise<UserResponse> {
    const response = await this.client.get<UserResponse>('/api/v1/users/me');
    return response.data;
  }

  async getUser(username: string): Promise<UserResponse> {
    const response = await this.client.get<UserResponse>(
      `/api/v1/users/${encodeURIComponent(username)}`
    );
    return response.data;
  }

  async searchUsers(query: string): Promise<SearchResponse> {
    const response = await this.client.post<SearchResponse>('/api/v1/search', {
      query,
      attributes: [
        'sAMAccountName',
        'displayName',
        'mail',
        'givenName',
        'sn',
        'dn',
      ],
      sizeLimit: 50,
    });
    return response.data;
  }

  async getAllGroups(baseDN?: string): Promise<GroupsResponse> {
    const params = baseDN ? `?baseDN=${encodeURIComponent(baseDN)}` : '';
    const response = await this.client.get<GroupsResponse>(
      `/api/v1/groups${params}`
    );
    return response.data;
  }

  async searchGroups(query: string): Promise<GroupsResponse> {
    const response = await this.client.get<GroupsResponse>(
      `/api/v1/groups?query=${encodeURIComponent(query)}`
    );
    return response.data;
  }

  async addUserToGroup(
    username: string,
    groupName: string
  ): Promise<APIResponse> {
    try {
      const response = await this.client.post<APIResponse>(
        '/api/v1/groups/add-member',
        { username, groupName }
      );
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.data) {
        return error.response.data as APIResponse;
      }
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }

  async removeUserFromGroup(
    username: string,
    groupName: string
  ): Promise<APIResponse> {
    try {
      const response = await this.client.post<APIResponse>(
        '/api/v1/groups/remove-member',
        { username, groupName }
      );
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.data) {
        return error.response.data as APIResponse;
      }
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }

  async changePassword(
    oldPassword: string,
    newPassword: string
  ): Promise<APIResponse> {
    try {
      const response = await this.client.post<APIResponse>(
        '/api/v1/users/change-password',
        { oldPassword, newPassword }
      );
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.data) {
        return error.response.data as APIResponse;
      }
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.client.get('/health');
      return response.data.status === 'healthy';
    } catch {
      return false;
    }
  }
}

export const api = new ApiService();
export default api;
