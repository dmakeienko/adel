export interface PasswordValidation {
  minLength: boolean;
  hasNumber: boolean;
  hasCapital: boolean;
  hasSpecial: boolean;
}

export function validatePassword(password: string): PasswordValidation {
  return {
    minLength: password.length >= 9,
    hasNumber: /\d/.test(password),
    hasCapital: /[A-Z]/.test(password),
    hasSpecial: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password),
  };
}

export function isPasswordComplex(validation: PasswordValidation): boolean {
  return validation.minLength && validation.hasNumber &&
    validation.hasCapital && validation.hasSpecial;
}
