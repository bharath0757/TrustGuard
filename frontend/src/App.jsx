import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { TrustGuardProvider } from './context/TrustGuardContext';
import { AppRoutes } from './routes';

export default function App() {
  return (
    <BrowserRouter>
      <TrustGuardProvider>
        <AppRoutes />
      </TrustGuardProvider>
    </BrowserRouter>
  );
}
