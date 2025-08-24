
import { ref, onMounted } from "vue";
import { UserManager, WebStorageStateStore, User } from 'oidc-client-ts';

// Read runtime/build-time configuration from Vite env (set via Docker build-args or .env)
const AUTHORITY = import.meta.env.VITE_OIDC_AUTHORITY || 'http://localhost:18888';
const CLIENT_ID = import.meta.env.VITE_OIDC_CLIENT_ID || 'test-client';
const REDIRECT_URI = import.meta.env.VITE_OIDC_REDIRECT_URI || 'http://localhost:5173/callback';
const POST_LOGOUT_REDIRECT_URI = import.meta.env.VITE_OIDC_POST_LOGOUT_REDIRECT_URI || 'http://localhost:5173';
const SCOPE = import.meta.env.VITE_OIDC_SCOPES || 'openid profile email';

const settings = {
  authority: AUTHORITY,
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  response_type: 'code', // Authorization Code Flow
  scope: SCOPE,
  post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
  userStore: new WebStorageStateStore({ store: window.sessionStorage }), 
};

const userManager = new UserManager(settings);

export const authService = {
  login(): Promise<void> {
    return userManager.signinRedirect();
  },

  logout(): Promise<void> {
    return userManager.signoutRedirect();
  },

  handleCallback(): Promise<User> {
    return userManager.signinRedirectCallback();
  },

  getUser(): Promise<User | null> {
    return userManager.getUser();
  },

  async getAccessToken(): Promise<string | null> {
    const user = await userManager.getUser();
    return user ? user.access_token : null;
  },

  renewToken(): Promise<User | null> {
    return userManager.signinSilent();
  }
};

const user = ref<User | null>(null);
const isAuthenticated = ref(false);

export function useAuth() {
  const checkAuth = async () => {
    const currentUser = await authService.getUser();
    user.value = currentUser;
    isAuthenticated.value = !!currentUser && !currentUser.expired;
  };

  onMounted(checkAuth);

  const login = () => authService.login();
  const logout = () => authService.logout();

  // アプリケーション全体で認証状態の変更を検知できるようにする
  // (例: 別のタブでログアウトした場合など)
  // userManager.events.addUserLoaded(user => { ... });
  
  return {
    user,
    isAuthenticated,
    login,
    logout,
    checkAuth
  };
}