"use client";
import { useState } from "react";
import { signIn, completeNewPassword, verifyMfaSetup, sendTotp, SignInStep } from "@/lib/auth";

// Accounts are created by an administrator in the Cognito user pool (no
// self-service sign-up) and added to the spm-admins or spm-viewers group. Every
// sign-in requires a TOTP code; the first sign-in sets a permanent password and
// enrolls an authenticator app.
const inputCls = "w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20 transition placeholder:text-gray-600";

export default function LoginPage() {
  const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState(""); const [code, setCode] = useState("");
  const [step, setStep] = useState<SignInStep | null>(null);
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault(); setError(""); setLoading(true);
    try {
      let next: SignInStep;
      if (!step) next = await signIn(email, password);
      else if (step.kind === "newPassword") next = await completeNewPassword(step.user, email, newPassword);
      else if (step.kind === "mfaSetup") next = await verifyMfaSetup(step.user, code.trim());
      else if (step.kind === "totp") next = await sendTotp(step.user, code.trim());
      else return;
      setCode("");
      if (next.kind === "done") { window.location.href = "/"; return; }
      setStep(next);
    } catch (err: any) {
      setError(err?.message || "Error");
    } finally {
      setLoading(false);
    }
  }

  const title = !step ? "Sign in to continue"
    : step.kind === "newPassword" ? "Set a new password"
    : step.kind === "mfaSetup" ? "Set up your authenticator app"
    : "Enter your authenticator code";

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
          <p className="text-sm text-gray-400 text-center">{title}</p>
          {error && <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-red-400 text-sm">{error}</div>}

          {!step && <>
            <input value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" type="email" autoComplete="username" className={inputCls} />
            <input value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" type="password" autoComplete="current-password" className={inputCls} />
          </>}

          {step?.kind === "newPassword" &&
            <input value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="New password (14+ characters)" type="password" autoComplete="new-password" className={inputCls} />}

          {step?.kind === "mfaSetup" && <div className="space-y-2 text-xs text-gray-400">
            <p>Add this key to an authenticator app, then enter the 6-digit code it shows.</p>
            <code className="block break-all bg-white/[0.03] border border-white/10 rounded-lg p-2 text-gray-200 select-all">{step.secret}</code>
            <p className="break-all text-gray-600">{step.otpauthUri}</p>
          </div>}

          {(step?.kind === "mfaSetup" || step?.kind === "totp") &&
            <input value={code} onChange={e => setCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" autoComplete="one-time-code" className={inputCls} />}

          <button type="submit" disabled={loading}
            className="w-full bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 disabled:opacity-50 py-2.5 rounded-xl text-sm font-medium transition shadow-lg shadow-red-500/20">
            {loading ? "..." : step ? "Continue" : "Sign In"}
          </button>
          <p className="text-[11px] text-gray-600 text-center">Accounts are created by your AI SPM administrator.</p>
        </div>
      </form>
    </div>
  );
}
