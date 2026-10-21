import { createContext, useContext, useEffect, useState } from "react";
import { api, getToken, setToken, clearToken } from "./api";

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // On page load: if a token is saved, ask the server who it belongs to
  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then(setUser)
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  const saveSession = (data) => {
    setToken(data.token);
    setUser(data.user);
  };

  const login = async (email, password) =>
    saveSession(await api.login({ email, password }));

  const register = async (name, email, password) =>
    saveSession(await api.register({ name, email, password }));

  const logout = () => {
    clearToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}