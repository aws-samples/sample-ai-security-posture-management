"use client";
import { useState } from "react";
import { signIn } from "@/lib/auth";

// Accounts are created by an administrator in the Cognito user pool and added
// to the spm-admins or spm-viewers group; there is no self-service sign-up.
export default function LoginPage() {
  const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault(); setError(""); setLoading(true);
    try {
      await signIn(email, password); window.location.href = "/";
    } catch (err: any) {
      setError(err?.message === "NEW_PASSWORD_REQUIRED"
        ? "Your administrator must set a permanent password for this account."
        : err?.message || "Error");
    }
    setLoading(false);
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center">
      <form onSubmit={handleSubmit} className="w-[380px]">
        <div className="flex items-center gap-2.5 justify-center mb-8">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-orange-600 flex items-center justify-center text-white text-lg font-bold">S</div>
          <div>
            <span className="font-bold text-xl text-white tracking-tight">AI SPM</span>
            <span className="text-[10px] text-red-400 block -mt-0.5 tracking-widest uppercase">Security Posture</span>
          </div>
        </div>

        <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6 space-y-4">
          <p className="text-sm text-gray-400 text-center">Sign in to continue</p>
          {error && <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-red-400 text-sm">{error}</div>}
          <input value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" type="email"
            className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20 transition placeholder:text-gray-600" />
          <input value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" type="password"
            className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20 transition placeholder:text-gray-600" />
          <button type="submit" disabled={loading}
            className="w-full bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 disabled:opacity-50 py-2.5 rounded-xl text-sm font-medium transition shadow-lg shadow-red-500/20">
            {loading ? "..." : "Sign In"}
          </button>
          <p className="text-[11px] text-gray-600 text-center">Accounts are created by your AI SPM administrator.</p>
        </div>
      </form>
    </div>
  );
}
