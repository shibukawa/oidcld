import { createRouter, createWebHistory } from 'vue-router';
import HomeView from './HomeView.vue';
import ProfileView from './ProfileView.vue';
import CallbackView from './CallbackView.vue';
import { authService } from './authService';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView
    },
    {
      path: '/profile',
      name: 'profile',
      component: ProfileView,
      meta: { requiresAuth: true } // このルートは認証が必要
    },
    {
      path: '/callback',
      name: 'callback',
      component: CallbackView
    }
  ]
});

router.beforeEach(async (to, _from, next) => {
  const requiresAuth = to.matched.some(record => record.meta.requiresAuth);
  const user = await authService.getUser();
  const isAuthenticated = !!user && !user.expired;

  if (requiresAuth && !isAuthenticated) {
    authService.login();
  } else {
    next();
  }
});

export default router;