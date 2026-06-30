import { describe, it, expect, vi } from 'vitest';
import { render, screen, act, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { NotificationBanner } from '../components/NotificationBanner';
import { NotificationProvider, useNotification } from '../contexts/NotificationContext';

function Trigger({ message, type }: { message: string; type?: 'success' | 'error' | 'info' | 'warning' }) {
  const { showNotification } = useNotification();
  return <button onClick={() => showNotification(message, type)}>show</button>;
}

function setup(message: string, type?: 'success' | 'error' | 'info' | 'warning') {
  return render(
    <NotificationProvider>
      <Trigger message={message} type={type} />
      <NotificationBanner />
    </NotificationProvider>
  );
}

describe('NotificationBanner', () => {
  it('renders nothing when there are no notifications', () => {
    const { container } = render(
      <NotificationProvider>
        <NotificationBanner />
      </NotificationProvider>
    );
    expect(container.querySelector('.notification-container')).toBeNull();
  });

  it('displays a notification after showNotification is called', async () => {
    setup('Login successful', 'success');
    await userEvent.click(screen.getByRole('button', { name: 'show' }));
    expect(screen.getByText('Login successful')).toBeInTheDocument();
  });

  it('applies the correct CSS class for the notification type', async () => {
    setup('Something went wrong', 'error');
    await userEvent.click(screen.getByRole('button', { name: 'show' }));
    const notification = screen.getByText('Something went wrong').closest('.notification');
    expect(notification).toHaveClass('notification-error');
  });

  it('removes the notification when the close button is clicked', async () => {
    setup('Dismissible', 'info');
    await userEvent.click(screen.getByRole('button', { name: 'show' }));
    expect(screen.getByText('Dismissible')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /close notification/i }));
    expect(screen.queryByText('Dismissible')).not.toBeInTheDocument();
  });

  it('auto-removes the notification after the duration expires', () => {
    vi.useFakeTimers();
    setup('Temporary', 'warning');
    act(() => { fireEvent.click(screen.getByRole('button', { name: 'show' })); });
    expect(screen.getByText('Temporary')).toBeInTheDocument();
    act(() => { vi.advanceTimersByTime(10001); });
    expect(screen.queryByText('Temporary')).not.toBeInTheDocument();
    vi.useRealTimers();
  });
});
