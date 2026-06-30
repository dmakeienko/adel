import { createContext, useContext, useCallback, type ReactNode } from 'react';
import { toast } from 'sonner';

type NotificationType = 'success' | 'error' | 'info' | 'warning';

interface NotificationContextType {
  showNotification: (message: string, type?: NotificationType, duration?: number) => void;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);

export function NotificationProvider({ children }: { children: ReactNode }) {
  const showNotification = useCallback(
    (message: string, type: NotificationType = 'info', duration: number = 10000) => {
      const opts = { duration };
      switch (type) {
        case 'success': toast.success(message, opts); break;
        case 'error':   toast.error(message, opts);   break;
        case 'warning': toast.warning(message, opts); break;
        default:        toast.info(message, opts);    break;
      }
    },
    []
  );

  return (
    <NotificationContext.Provider value={{ showNotification }}>
      {children}
    </NotificationContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useNotification() {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
}
