import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { TrustGuardProvider } from './context/TrustGuardContext';
import { AppRoutes } from './routes';

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <TrustGuardProvider>
          <AppRoutes />
        </TrustGuardProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
