import { useContext } from 'react';
import { TrustGuardContext } from '../context/TrustGuardContext';

export function useTrustGuard() {
  const context = useContext(TrustGuardContext);
  if (!context) {
    throw new Error('useTrustGuard must be used within a TrustGuardProvider');
  }
  return context;
}
