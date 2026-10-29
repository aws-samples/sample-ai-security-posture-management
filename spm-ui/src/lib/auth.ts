import { CognitoUserPool, CognitoUser, AuthenticationDetails, CognitoUserSession } from "amazon-cognito-identity-js";

const POOL_ID = process.env.NEXT_PUBLIC_COGNITO_POOL_ID || "";
const CLIENT_ID = process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID || "";

// Tokens live in sessionStorage, not the library's localStorage default: they
// are dropped when the tab closes and are not shared across tabs. Any storage
// readable by JavaScript is exposed to XSS, so the dashboard also sends a
// strict nonce-based CSP (src/middleware.ts) and the Cognito client issues
// 15-minute ID/access tokens and 8-hour refresh tokens.
const storage = typeof window !== "undefined" ? window.sessionStorage : undefined;
const userPool = new CognitoUserPool({ UserPoolId: POOL_ID, ClientId: CLIENT_ID, Storage: storage });

export function getCurrentUser(): CognitoUser | null { return userPool.getCurrentUser(); }

export function getSession(): Promise<CognitoUserSession> {
  return new Promise((resolve, reject) => {
    const user = getCurrentUser();
    if (!user) return reject(new Error("No user"));
    user.getSession((err: Error | null, session: CognitoUserSession | null) => {
      if (err || !session) return reject(err || new Error("No session"));
      resolve(session);
    });
  });
}

export async function getToken(): Promise<string> {
  const session = await getSession();
  return session.getIdToken().getJwtToken();
}

/** Result of a sign-in step: done, or the next challenge the user must answer. */
export type SignInStep =
  | { kind: "done" }
  | { kind: "newPassword"; user: CognitoUser }
  | { kind: "mfaSetup"; user: CognitoUser; secret: string; otpauthUri: string }
  | { kind: "totp"; user: CognitoUser };

function callbacks(user: CognitoUser, email: string,
                   resolve: (s: SignInStep) => void, reject: (e: unknown) => void) {
  return {
    onSuccess: () => resolve({ kind: "done" }),
    onFailure: reject,
    newPasswordRequired: () => resolve({ kind: "newPassword", user }),
    totpRequired: () => resolve({ kind: "totp", user }),
    // The pool requires TOTP MFA; first sign-in enrolls an authenticator app.
    mfaSetup: () => user.associateSoftwareToken({
      associateSecretCode: (secret: string) => resolve({
        kind: "mfaSetup", user, secret,
        otpauthUri: `otpauth://totp/AI%20SPM:${encodeURIComponent(email)}?secret=${secret}&issuer=AI%20SPM`,
      }),
      onFailure: reject,
    }),
    mfaRequired: () => reject(new Error("SMS MFA is not supported; use an authenticator app.")),
  };
}

export function signIn(email: string, password: string): Promise<SignInStep> {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: email, Pool: userPool, Storage: storage });
    user.authenticateUser(new AuthenticationDetails({ Username: email, Password: password }),
      callbacks(user, email, resolve, reject));
  });
}

/** Set a permanent password for an administrator-created account. */
export function completeNewPassword(user: CognitoUser, email: string, newPassword: string): Promise<SignInStep> {
  return new Promise((resolve, reject) => {
    user.completeNewPasswordChallenge(newPassword, {}, callbacks(user, email, resolve, reject));
  });
}

/** Confirm authenticator-app enrollment with its first code. */
export function verifyMfaSetup(user: CognitoUser, code: string): Promise<SignInStep> {
  return new Promise((resolve, reject) => {
    user.verifySoftwareToken(code, "authenticator", {
      onSuccess: () => resolve({ kind: "done" }),
      onFailure: reject,
    });
  });
}

/** Answer the TOTP challenge on a normal sign-in. */
export function sendTotp(user: CognitoUser, code: string): Promise<SignInStep> {
  return new Promise((resolve, reject) => {
    user.sendMFACode(code, { onSuccess: () => resolve({ kind: "done" }), onFailure: reject },
      "SOFTWARE_TOKEN_MFA");
  });
}

export function signOut(): void { getCurrentUser()?.signOut(); }
