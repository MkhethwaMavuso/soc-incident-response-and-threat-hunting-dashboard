import axios from 'axios'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? (import.meta.env.DEV ? '/api' : `${window.location.origin}/api`),
  timeout: 8000,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('soc-token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})