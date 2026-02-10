import { HashRouter, Routes, Route, Navigate } from "react-router-dom"
import MainLayout from "@/layouts/MainLayout"
import Login from "@/pages/auth/Login"
import Register from "@/pages/auth/Register"
import Otp from "@/pages/auth/Otp"
import Dashboard from "@/pages/Dashboard"
import Projects from "@/pages/Projects"
import Resources from "@/pages/Resources"
import Quality from "@/pages/Quality"
import Workload from "@/pages/Workload"
import Settings from "@/pages/Settings"
import { useAuthStore } from "@/store/useAuthStore"

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/otp" element={<Otp />} />
        
        <Route path="/" element={
          <ProtectedRoute>
            <MainLayout />
          </ProtectedRoute>
        }>
          <Route index element={<Dashboard />} />
          <Route path="projects" element={<Projects />} />
          <Route path="resources" element={<Resources />} />
          <Route path="quality" element={<Quality />} />
          <Route path="workload" element={<Workload />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </HashRouter>
  )
}
