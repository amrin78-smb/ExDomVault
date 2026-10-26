export type ButtonVariant = 'primary' | 'secondary' | 'danger';

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-accent text-accent-fg hover:bg-accent-hover shadow-[0_0_0_1px_rgb(59_130_246/0.5),0_4px_14px_-6px_rgb(37_99_235/0.7)] disabled:opacity-50 disabled:shadow-none',
  secondary:
    'border border-line-strong bg-surface text-fg-2 hover:bg-surface-3 hover:text-fg disabled:text-fg-faint disabled:hover:bg-surface',
  danger: 'bg-[#b91c1c] text-white hover:bg-[#991b1b] disabled:opacity-50',
};

export const buttonClass = (variant: ButtonVariant = 'secondary') =>
  `inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium shadow-sm transition-colors disabled:cursor-not-allowed ${VARIANTS[variant]}`;
