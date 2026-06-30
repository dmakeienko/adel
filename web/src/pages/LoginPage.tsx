import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useNotification } from '../contexts/NotificationContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent } from '@/components/ui/card';

export function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const { login } = useAuth();
  const { showNotification } = useNotification();
  const navigate = useNavigate();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      showNotification('Please enter username and password', 'warning');
      return;
    }

    setIsLoading(true);
    try {
      const result = await login({ username, password });
      if (result.success) {
        showNotification('Login successful! Welcome to ADEL.', 'success', 10000);
        navigate(`/user/${username}`);
      } else {
        const message =
          result.status === 401 ? 'Invalid username or password' :
          result.status === 403 ? 'Account is disabled or locked' :
          result.status === 429 ? 'Too many login attempts. Please wait before trying again.' :
          result.status === 503 ? 'Service unavailable. Please try again later.' :
          result.message || 'Login failed';
        showNotification(message, 'error');
      }
    } catch {
      showNotification('An unexpected error occurred during login', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-sidebar p-5">
      <Card className="w-full max-w-[440px] shadow-2xl border-0">
        <CardContent className="pt-12 pb-10 px-12 text-center">
          {/* Branding */}
          <div className="mb-8">
            <div className="flex items-center justify-center mb-5">
              <img src="/logo.svg" alt="ADEL" className="w-40 h-40" />
            </div>
            <p className="text-s font-bold text-muted-foreground uppercase tracking-wider mb-4 whitespace-nowrap">
              Active Directory Engagement Layer
            </p>
            <p className="text-sm text-muted-foreground leading-relaxed">
              A secure web interface for managing Active Directory users and
              groups.
            </p>
            <p className="text-sm text-muted-foreground">Connect to your organization's directory service with your
              existing credentials.
            </p>
          </div>

          {!showForm ? (
            <Button
              className="w-full py-6 text-base"
              onClick={() => setShowForm(true)}
            >
              Log In
            </Button>
          ) : (
            <form className="text-left space-y-5" onSubmit={handleSubmit}>
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your AD username"
                  autoComplete="username"
                  disabled={isLoading}
                  autoFocus
                  className=""
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    id="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    disabled={isLoading}
                    className="pr-11"
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                    onClick={() => setShowPassword(!showPassword)}
                    tabIndex={-1}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              <div className="flex gap-3 pt-1">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => setShowForm(false)}
                  disabled={isLoading}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="flex-1"
                  disabled={isLoading}
                >
                  {isLoading ? 'Signing in...' : 'Sign In'}
                </Button>
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
