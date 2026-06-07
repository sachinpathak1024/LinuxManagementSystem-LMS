// Thin API client with bearer-token auth.
const Api = (() => {
  const TOKEN_KEY = "sentinel_token";

  const getToken = () => localStorage.getItem(TOKEN_KEY);
  const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);
  const clearToken = () => localStorage.removeItem(TOKEN_KEY);

  async function request(path, opts = {}) {
    const headers = opts.headers || {};
    const token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    const res = await fetch(path, { ...opts, headers });
    if (res.status === 401) {
      clearToken();
      window.location.reload();
      throw new Error("unauthorized");
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!res.ok) {
      const msg = (data && data.detail) ? data.detail : ("HTTP " + res.status);
      throw new Error(msg);
    }
    return data;
  }

  async function login(username, password) {
    const body = new URLSearchParams({ username, password });
    const res = await fetch("/api/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error(d.detail || "Login failed");
    }
    const data = await res.json();
    setToken(data.access_token);
    return data;
  }

  const get = (p) => request(p);
  const post = (p, body) =>
    request(p, { method: "POST", headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : null });
  const del = (p) => request(p, { method: "DELETE" });

  return { login, get, post, del, getToken, clearToken };
})();
