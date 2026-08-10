import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react';
import type { User, LoginRequest } from '../types';
import api from '../services/api';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  /**
   * Whether the current session may use the search endpoint. Defaults to false
   * until the session is loaded so search controls never flash for a user who is
   * not permitted to use them. The server-side check is the real enforcement.
   */
  canSearch: boolean;
  login: (credentials: LoginRequest) => Promise<{ success: boolean; message?: string; status?: number }>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [canSearch, setCanSearch] = useState(false);

  const refreshSearchPermission = useCallback(async () => {
    try {
      const info = await api.getSessionInfo();
      setCanSearch(info?.canSearch ?? false);
    } catch {
      setCanSearch(false);
    }
  }, []);

  const refreshUser = useCallback(async () => {
    if (!api.getSessionId()) {
      setUser(null);
      setCanSearch(false);
      setIsLoading(false);
      return;
    }

    try {
      const response = await api.getCurrentUser();
      if (response.success && response.user) {
        setUser(response.user);
        setIsAuthenticated(true);
        await refreshSearchPermission();
      } else {
        setUser(null);
        setIsAuthenticated(false);
        setCanSearch(false);
        api.setSessionId(null);
      }
    } catch {
      setUser(null);
      setIsAuthenticated(false);
      setCanSearch(false);
      api.setSessionId(null);
    } finally {
      setIsLoading(false);
    }
  }, [refreshSearchPermission]);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = async (
    credentials: LoginRequest
  ): Promise<{ success: boolean; message?: string; status?: number }> => {
    const response = await api.login(credentials);
    if (response.success) {
      setUser(response.user ?? null);
      setIsAuthenticated(true);
      await refreshSearchPermission();
      return { success: true };
    }
    return { success: false, message: response.message, status: response.status };
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      // Ignore logout errors
    } finally {
      setUser(null);
      setIsAuthenticated(false);
      setCanSearch(false);
      api.setSessionId(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        canSearch,
        login,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
