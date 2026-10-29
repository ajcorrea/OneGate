import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import "./theme.css";
import { AuthProvider, useAuth } from "./auth";
import { ThemeProvider } from "./theme";
import { Layout } from "./components/Layout";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Customers } from "./pages/Customers";
import { Staff } from "./pages/Staff";
import { Audit } from "./pages/Audit";

function App() {
  const { me, loading } = useAuth();
  if (loading) return null;
  if (!me) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="clientes" element={<Customers />} />
        {me.is_admin && <Route path="equipe" element={<Staff />} />}
        <Route path="auditoria" element={<Audit />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  </StrictMode>,
);
