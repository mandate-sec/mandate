const TOKEN_KEY = "artex_token";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 days (seconds)

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  onSessionChange(listener: () => void): () => void {
    const onStorage = (event: StorageEvent) => {
      if (event.storageArea === window.localStorage && (event.key === TOKEN_KEY || event.key === null)) {
        listener();
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  },

  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo: no real login; return a fake token so the route guard passes and goes straight to the main UI.
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // Also write a cookie so the Next.js middleware can read it server-side
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax${secure}`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
  },

  // Parse the current user from the JWT payload's sub field; display only, no signature verification.
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url -> base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "ARTEX";
      return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
    } catch {
      return null;
    }
  },
};

export function isSessionRejected(response: Response): boolean {
  return response.status === 401 && response.headers.get("WWW-Authenticate") === "Bearer";
}

export async function fetchConsoleAPI(path: string, init?: RequestInit): Promise<Response> {
  const authorization = new Headers(init?.headers).get("Authorization");
  const response = await fetch(path, { ...init, mode: "same-origin" });
  if (isSessionRejected(response) && authorization) {
    const currentToken = auth.getToken();
    // Other tabs can sign in while the request is in flight. Discard the
    // session only when the rejected credential is still the active one.
    if (currentToken && authorization === `Bearer ${currentToken}`) {
      auth.clearToken();
      window.location.replace("/login");
    }
  }
  return response;
}
