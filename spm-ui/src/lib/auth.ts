import { CognitoUserPool, CognitoUser, AuthenticationDetails, CognitoUserSession } from "amazon-cognito-identity-js";

const POOL_ID = process.env.NEXT_PUBLIC_COGNITO_POOL_ID || "";
const CLIENT_ID = process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID || "";
const userPool = new CognitoUserPool({ UserPoolId: POOL_ID, ClientId: CLIENT_ID });

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

export function signIn(email: string, password: string): Promise<CognitoUserSession> {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: email, Pool: userPool });
    user.authenticateUser(new AuthenticationDetails({ Username: email, Password: password }), {
      onSuccess: resolve, onFailure: reject,
      newPasswordRequired: () => reject(new Error("NEW_PASSWORD_REQUIRED")),
    });
  });
}

export function signOut(): void { getCurrentUser()?.signOut(); }
