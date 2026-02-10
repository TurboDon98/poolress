import { useSettingsStore } from '@/store/useSettingsStore';

export const fetchApi = async (endpoint: string, options: RequestInit = {}) => {
  const backendUrl = useSettingsStore.getState().backendUrl.replace(/\/$/, ''); // Remove trailing slash
  const url = endpoint.startsWith('http') ? endpoint : `${backendUrl}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  
  const response = await fetch(url, options);
  return response;
};
