import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { DashboardLayout } from './components/DashboardLayout';

// Pages
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Endpoints from './pages/Endpoints';
import EndpointDetail from './pages/EndpointDetail';
import Policies from './pages/Policies';
import PolicyCreate from './pages/PolicyCreate';
import Alerts from './pages/Alerts';
import Network from './pages/Network';
import MLEngine from './pages/MLEngine';

const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#1e293b',
              color: '#e2e8f0',
              border: '1px solid #334155',
              borderRadius: '8px',
            },
            success: { iconTheme: { primary: '#3b82f6', secondary: '#fff' } },
            error: { iconTheme: { primary: '#ef4444', secondary: '#fff' } },
          }}
        />
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<DashboardLayout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/endpoints" element={<Endpoints />} />
              <Route path="/endpoints/:id" element={<EndpointDetail />} />
              <Route path="/policies" element={<Policies />} />
              <Route path="/policies/new" element={<PolicyCreate />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/network" element={<Network />} />
              <Route path="/ml" element={<MLEngine />} />
            </Route>
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
