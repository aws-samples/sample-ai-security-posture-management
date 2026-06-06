"use client";
import { ReactNode, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { AuthProvider, useAuth } from "./AuthProvider";
import { Sidebar } from "./Sidebar";

function AuthGate({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user && pathname !== "/login") router.push("/login");
  }, [user, loading, pathname, router]);

  if (loading) return (
    <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center">
      <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-orange-600 animate-pulse" />
    </div>
  );
  if (pathname === "/login") return <>{children}</>;
  if (!user) return null;

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  );
}

export function AuthGuard({ children }: { children: ReactNode }) {
  return <AuthProvider><AuthGate>{children}</AuthGate></AuthProvider>;
}
