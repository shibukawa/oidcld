<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router';
import { useAuth } from './authService';

const { isAuthenticated, login, logout } = useAuth();
</script>

<template>
  <div id="app" class="min-h-screen flex flex-col">
    <header class="glass sticky top-0 z-50 border-b border-slate-200 shadow-sm">
      <div class="max-w-7xl mx-auto px-4">
        <div class="flex items-center justify-between py-4 gap-8">
          <div class="flex-shrink-0">
            <h1 class="text-2xl font-bold text-slate-800 flex items-center gap-2">
              <span class="text-3xl">🔐</span>
              <span class="gradient-text">OpenID Connect for Local Development</span>
            </h1>
          </div>
          
          <nav class="hidden md:flex items-center gap-6 flex-1 justify-center">
            <RouterLink 
              to="/" 
              class="flex items-center gap-2 px-4 py-2 text-slate-600 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200 font-medium"
              :class="{ 'text-blue-600 bg-blue-50 font-semibold': $route.path === '/' }"
            >
              <span class="text-lg">🏠</span>
              Home
            </RouterLink>
            <RouterLink 
              v-if="isAuthenticated" 
              to="/profile" 
              class="flex items-center gap-2 px-4 py-2 text-slate-600 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200 font-medium"
              :class="{ 'text-blue-600 bg-blue-50 font-semibold': $route.path === '/profile' }"
            >
              <span class="text-lg">👤</span>
              Profile
            </RouterLink>
          </nav>
          
          <div class="flex items-center gap-4 flex-shrink-0">
            <div v-if="isAuthenticated" class="hidden sm:flex items-center">
              <span class="inline-flex items-center gap-2 px-3 py-1 bg-green-100 text-green-700 rounded-full text-sm font-medium border border-green-200">
                <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                Authenticated
              </span>
            </div>
            <button 
              v-if="!isAuthenticated" 
              @click="login" 
              class="btn-gradient text-white px-6 py-2 rounded-lg font-semibold flex items-center gap-2 hover:-translate-y-0.5 transition-all duration-200 shadow-md hover:shadow-lg"
            >
              <span>🚀</span>
              Sign In
            </button>
            <button 
              v-if="isAuthenticated" 
              @click="logout" 
              class="bg-slate-500 hover:bg-slate-600 text-white px-6 py-2 rounded-lg font-semibold flex items-center gap-2 hover:-translate-y-0.5 transition-all duration-200 shadow-md"
            >
              <span>👋</span>
              Sign Out
            </button>
          </div>
        </div>
        
        <!-- Mobile Navigation -->
        <nav class="md:hidden flex items-center justify-center gap-4 pb-4">
          <RouterLink 
            to="/" 
            class="flex items-center gap-2 px-3 py-2 text-slate-600 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200 font-medium text-sm"
            :class="{ 'text-blue-600 bg-blue-50 font-semibold': $route.path === '/' }"
          >
            <span>🏠</span>
            Home
          </RouterLink>
          <RouterLink 
            v-if="isAuthenticated" 
            to="/profile" 
            class="flex items-center gap-2 px-3 py-2 text-slate-600 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200 font-medium text-sm"
            :class="{ 'text-blue-600 bg-blue-50 font-semibold': $route.path === '/profile' }"
          >
            <span>👤</span>
            Profile
          </RouterLink>
        </nav>
      </div>
    </header>

    <main class="flex-1 py-8">
      <div class="max-w-7xl mx-auto px-4">
        <RouterView />
      </div>
    </main>

    <footer class="glass border-t border-slate-200 py-6 mt-auto">
      <div class="max-w-7xl mx-auto px-4">
        <p class="text-center text-slate-600 text-sm">
          OpenID Connect for Local Development • 
          <a href="https://github.com/shibukawa/oidcld" target="_blank" class="text-blue-600 hover:text-blue-700 font-medium hover:underline">
            View on GitHub
          </a>
        </p>
      </div>
    </footer>
  </div>
</template>

<style scoped>
/* App-specific styles can be added here if needed */
</style>
