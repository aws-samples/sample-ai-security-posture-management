"use client";
import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { getCurrentUser, getSession, signOut as cognitoSignOut } from "@/lib/auth";

interface AuthState { user: { email: string; sub: string } | null; loading: boolean; signOut: () => void; }
const AuthContext = createContext<AuthState>({ user: null, loading: true, signOut: () => {} });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<{ email: string; sub: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSession()
      .then((s) => { const p = s.getIdToken().decodePayload(); setUser({ email: p.email, sub: p.sub }); })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const handleSignOut = () => { cognitoSignOut(); setUser(null); window.location.href = "/login"; };

  return <AuthContext.Provider value={{ user, loading, signOut: handleSignOut }}>{children}</AuthContext.Provider>;
}

export function useAuth() { return useContext(AuthContext); }
