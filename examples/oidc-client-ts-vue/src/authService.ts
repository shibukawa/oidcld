
import { ref, onMounted } from "vue";
import { UserManager, WebStorageStateStore, User } from 'oidc-client-ts';

const settings = {
  authority: 'http://localhost:18888',
  client_id: 'test-client',
  redirect_uri: 'http://localhost:5173/callback',
  response_type: 'code', // Authorization Code Flow
  scope: 'openid profile email',
  post_logout_redirect_uri: 'http://localhost:5173',
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