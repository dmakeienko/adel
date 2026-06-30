import { Toaster } from '@/components/ui/sonner';

export function NotificationBanner() {
  return (
    <Toaster
      position="bottom-right"
      richColors
      closeButton
    />
  );
}
