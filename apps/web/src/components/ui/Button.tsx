import type { ButtonHTMLAttributes } from 'react';
import { buttonClass, type ButtonVariant } from './button-styles.ts';

export function Button({
  variant = 'secondary',
  className = '',
  type = 'button',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return <button type={type} className={`${buttonClass(variant)} ${className}`} {...props} />;
}
