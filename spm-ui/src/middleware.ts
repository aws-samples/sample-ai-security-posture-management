import { NextRequest, NextResponse } from "next/server";

// Per-request nonce-based Content-Security-Policy for every dashboard page.
// Next.js reads the nonce from the request's CSP header and applies it to its
// own scripts; with 'strict-dynamic', no other script can run, so injected
// markup cannot execute JavaScript or read the session tokens. connect-src
// limits where the page can send data to this origin, Cognito and (for local
// development) NEXT_PUBLIC_API_URL. CloudFront adds HSTS and related headers.
const POOL_ID = process.env.NEXT_PUBLIC_COGNITO_POOL_ID || "";
const API_URL = process.env.NEXT_PUBLIC_API_URL || "";
const COGNITO_REGION = POOL_ID.includes("_") ? POOL_ID.split("_")[0] : "";

function origin(url: string): string {
  try { return new URL(url).origin; } catch { return ""; }
}

export function middleware(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const dev = process.env.NODE_ENV === "development";
  const connect = ["'self'",
    COGNITO_REGION && `https://cognito-idp.${COGNITO_REGION}.amazonaws.com`,
    origin(API_URL)].filter(Boolean).join(" ");
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    // Inline style attributes are used by charts; style injection cannot run script.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    `connect-src ${connect}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [{
    source: "/((?!_next/static|_next/image|favicon.ico).*)",
    missing: [
      { type: "header", key: "next-router-prefetch" },
      { type: "header", key: "purpose", value: "prefetch" },
    ],
  }],
};
