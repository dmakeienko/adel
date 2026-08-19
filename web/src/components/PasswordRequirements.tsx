import { CheckCircle2, XCircle } from 'lucide-react';
import type { PasswordValidation } from '@/lib/password';

export function PasswordRequirements({
  validation,
  additionalRequirements = [],
}: {
  validation: PasswordValidation;
  additionalRequirements?: Array<{ met: boolean; label: string }>;
}) {
  return (
    <div className="p-4 bg-muted rounded-lg border border-border space-y-2">
      <p className="text-sm font-semibold text-foreground">Password must contain:</p>
      <ul className="space-y-2">
        <RequirementItem met={validation.minLength} label="At least 9 characters" />
        <RequirementItem met={validation.hasNumber} label="At least one number" />
        <RequirementItem met={validation.hasCapital} label="At least one capital letter" />
        <RequirementItem met={validation.hasSpecial} label="At least one special character" />
        {additionalRequirements.map((requirement) => (
          <RequirementItem key={requirement.label} {...requirement} />
        ))}
      </ul>
    </div>
  );
}

export function RequirementItem({ met, label }: { met: boolean; label: string }) {
  return (
    <li className={`flex items-center gap-2 text-sm transition-colors ${met ? 'text-green-600' : 'text-destructive'}`}>
      {met
        ? <CheckCircle2 className="w-4 h-4 shrink-0" />
        : <XCircle className="w-4 h-4 shrink-0" />}
      {label}
    </li>
  );
}
