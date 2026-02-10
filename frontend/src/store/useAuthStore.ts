import { create } from 'zustand'
import { fetchApi } from '@/lib/api'

export interface User {
  id: string
  email: string
  firstName: string // Имя
  lastName: string // Фамилия
  patronymic?: string // Отчество
  department: string
}

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (email: string, password?: string) => Promise<void>
  verifyOtp: (code: string) => Promise<boolean>
  register: (user: Omit<User, 'id'> & { password?: string }) => Promise<void>
  logout: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: false,
  login: async (email, password) => {
    set({ isLoading: true })
    try {
      const res = await fetchApi('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
      if (!res.ok) throw new Error('Login failed')
      
      const data = await res.json()
      if (data.ok && data.token) {
        const fullNameParts = (data.user.full_name || '').split(' ');
        const lastName = fullNameParts[0] || '';
        const firstName = fullNameParts[1] || '';
        const patronymic = fullNameParts.slice(2).join(' ') || '';
        
        set({
            isAuthenticated: true,
            user: {
                id: data.user.id,
                email: data.user.email,
                firstName,
                lastName,
                patronymic,
                department: data.user.department || ''
            }
        })
      }
    } catch (e) {
      console.error(e)
      throw e
    } finally {
      set({ isLoading: false })
    }
  },
  verifyOtp: async (code) => {
    set({ isLoading: true })
    // Mock OTP for now as backend doesn't have OTP endpoint yet
    await new Promise((resolve) => setTimeout(resolve, 1000))
    
    if (code === '1234') { 
       set((state) => ({ 
         isLoading: false, 
         isAuthenticated: true,
         user: state.user || { 
             id: '1',
             email: 'demo@turbo.project',
             firstName: 'Иван',
             lastName: 'Иванов',
             patronymic: 'Иванович',
             department: 'IT'
         }
       }))
       return true
    }
    set({ isLoading: false })
    return false
  },
  register: async (userData) => {
    set({ isLoading: true })
    try {
      const res = await fetchApi('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: userData.email,
          password: userData.password,
          username: userData.email.split('@')[0],
          full_name: `${userData.lastName} ${userData.firstName} ${userData.patronymic || ''}`.trim(),
          department: userData.department,
        }),
      })
      
      if (!res.ok) throw new Error('Registration failed')
      
      const data = await res.json()
      if (data.ok) {
         set({ 
            isLoading: false, 
            user: { ...userData, id: data.user.id },
            isAuthenticated: true 
        })
      }
    } catch (e) {
      console.error(e)
      set({ isLoading: false })
      throw e
    }
  },
  logout: () => set({ user: null, isAuthenticated: false }),
}))
