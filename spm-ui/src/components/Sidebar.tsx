"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "./AuthProvider";

const NAV = [
  { href: "/", label: "Dashboard", icon: "⬡" },
  { href: "/inventory", label: "Inventory", icon: "◈" },
  { href: "/topology", label: "Topology", icon: "◎" },
  { href: "/findings", label: "Findings", icon: "◉" },
  { href: "/policies", label: "Policies", icon: "◇" },
  { href: "/runtime", label: "Runtime", icon: "◆" },
  { href: "/settings", label: "Settings", icon: "⚙" },
  { href: "/about", label: "About", icon: "◇" },
];

export function Sidebar() {
  const path = usePathname();
  const { user, signOut } = useAuth();

  return (
    <nav className="w-60 bg-[#0d0d14] border-r border-white/5 flex flex-col">
      <div className="p-6 pb-8">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-orange-600 flex items-center justify-center text-white text-sm font-bold">S</div>
          <div>
            <span className="font-semibold text-white tracking-tight">AI SPM</span>
            <span className="text-[10px] text-red-400 block -mt-0.5 tracking-widest uppercase">Security Posture</span>
          </div>
        </Link>
      </div>

      <div className="flex-1 px-3 space-y-0.5">
        {NAV.map((n) => {
          const active = path === n.href;
          return (
            <Link key={n.href} href={n.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-medium transition-all ${
                active ? "bg-red-500/10 text-red-300 shadow-sm shadow-red-500/5"
                  : "text-gray-500 hover:text-gray-300 hover:bg-white/[0.03]"
              }`}>
              <span className={`text-base ${active ? "text-red-400" : "text-gray-600"}`}>{n.icon}</span>
              {n.label}
            </Link>
          );
        })}
      </div>

      <div className="p-4 border-t border-white/5 space-y-3">
        <div className="flex items-center gap-2 px-2">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-[11px] text-gray-600">3 pillars active</span>
        </div>
        {user && (
          <div className="flex items-center justify-between px-2">
            <span className="text-[11px] text-gray-500 truncate max-w-[140px]">{user.email}</span>
            <button onClick={signOut} className="text-[11px] text-gray-600 hover:text-red-400 transition">Sign out</button>
          </div>
        )}
      </div>
    </nav>
  );
}
