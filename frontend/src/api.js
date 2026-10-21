const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export const getToken = () => localStorage.getItem("token");
export const setToken = (t) => localStorage.setItem("token", t);
export const clearToken = () => localStorage.removeItem("token");

async function request(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(`${API}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error("Cannot reach the server. Is the backend running?");
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    /* response had no JSON body */
  }

  if (!res.ok) {
    let msg = "Something went wrong";
    if (data && typeof data.detail === "string") msg = data.detail;
    else if (data && Array.isArray(data.detail))
      msg = data.detail.map((d) => d.msg).join(", ");
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = {
  register: (body) => request("/auth/register", { method: "POST", body }),
  login: (body) => request("/auth/login", { method: "POST", body }),
  me: () => request("/auth/me"),
  analyzeUrl: (url) => request("/analyze/url", { method: "POST", body: { url } }),
  analyzeEmail: (raw) => request("/analyze/email", { method: "POST", body: { raw } }),
  scans: () => request("/scans"),
  stats: () => request("/stats"),
};