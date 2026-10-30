import "./globals.css";
import { AuthGuard } from "@/components/AuthGuard";

export const metadata = { title: "AI SPM — Security Posture Management" };
// Render per request so Next.js can apply the CSP nonce from src/middleware.ts.
export const dynamic = "force-dynamic";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en"><body><AuthGuard>{children}</AuthGuard></body></html>
  );
}
