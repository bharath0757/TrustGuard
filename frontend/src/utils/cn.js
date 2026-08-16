import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Merges Tailwind classes safely with clsx and twMerge
 */
export function cn(...inputs) {
  return twMerge(clsx(inputs));
}
