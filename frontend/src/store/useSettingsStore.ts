import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface SettingsState {
  backendUrl: string
  setBackendUrl: (url: string) => void
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      backendUrl: 'http://168.222.194.141:8000',
      setBackendUrl: (url) => set({ backendUrl: url }),
    }),
    {
      name: 'settings-storage',
    }
  )
)
