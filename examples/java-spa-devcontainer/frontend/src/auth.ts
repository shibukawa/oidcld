import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";

const authority = import.meta.env.VITE_OIDC_AUTHORITY || "https://oidc.localhost:8443";
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID || "quarkus-vue-client";
const redirectUri = import.meta.env.VITE_OIDC_REDIRECT_URI || "https://app.localhost:8443/callback";
const postLogoutRedirectUri =
  import.meta.env.VITE_OIDC_POST_LOGOUT_REDIRECT_URI || "https://app.localhost:8443/";
const scope = import.meta.env.VITE_OIDC_SCOPES || "openid profile email offline_access items.read items.write";

const userManager = new UserManager({
  authority,
  client_id: clientId,
  redirect_uri: redirectUri,
  response_type: "code",
  scope,
  post_logout_redirect_uri: postLogoutRedirectUri,
  userStore: new WebStorageStateStore({ store: window.sessionStorage })
});

export async function getUser(): Promise<User | null> {
  return userManager.getUser();
}

export async function getAccessToken(): Promise<string | null> {
  const user = await userManager.getUser();
  return user?.access_token ?? null;
}

export async function login(): Promise<void> {
  await userManager.signinRedirect();
}

export async function logout(): Promise<void> {
  await userManager.signoutRedirect();
}

export async function handleCallback(): Promise<User> {
  return userManager.signinRedirectCallback();
}

