<script setup lang="ts">
import { RouterLink } from 'vue-router';
import { useAuth } from './authService';

const { isAuthenticated } = useAuth();
</script>

<template>
  <div class="max-w-6xl mx-auto">
    <!-- Hero Section -->
    <div class="mb-12">
      <div class="glass rounded-2xl p-8 md:p-12 text-center shadow-xl">
        <div class="mb-8">
          <h1 class="text-4xl md:text-5xl font-bold mb-4 gradient-text">
            Welcome to OpenID Connect for Local Development
          </h1>
          <p class="text-xl text-slate-600 max-w-2xl mx-auto">
            Experience seamless authentication with our local development identity provider
          </p>
        </div>
        
        <div class="grid md:grid-cols-3 gap-8 mb-8">
          <div class="text-center p-6">
            <div class="text-5xl mb-4">🔒</div>
            <h3 class="text-xl font-semibold mb-2 text-slate-800">Secure Authentication</h3>
            <p class="text-slate-600">Industry-standard OpenID Connect protocol implementation</p>
          </div>
          <div class="text-center p-6">
            <div class="text-5xl mb-4">⚡</div>
            <h3 class="text-xl font-semibold mb-2 text-slate-800">Fast Integration</h3>
            <p class="text-slate-600">Quick setup for testing and development environments</p>
          </div>
          <div class="text-center p-6">
            <div class="text-5xl mb-4">🛠️</div>
            <h3 class="text-xl font-semibold mb-2 text-slate-800">Developer Friendly</h3>
            <p class="text-slate-600">Built specifically for testing and development workflows</p>
          </div>
        </div>
        
        <div class="flex flex-col sm:flex-row gap-4 justify-center items-center">
          <RouterLink 
            to="/profile" 
            class="btn-gradient text-white px-8 py-4 rounded-xl font-semibold flex flex-col items-center gap-2 hover:-translate-y-1 transition-all duration-300 shadow-lg hover:shadow-xl min-h-[4rem]"
          >
            <div class="flex items-center gap-2">
              <span class="text-xl">🚀</span>
              <span>Try Authentication</span>
            </div>
            <span class="text-sm opacity-80">Login required</span>
          </RouterLink>
          <a 
            href="https://github.com/shibukawa/oidcld" 
            target="_blank" 
            class="bg-white border-2 border-blue-600 text-blue-600 hover:bg-blue-600 hover:text-white px-8 py-4 rounded-xl font-semibold flex items-center gap-2 hover:-translate-y-1 transition-all duration-300 shadow-lg hover:shadow-xl min-h-[4rem]"
          >
            <span class="text-xl">📚</span>
            <span>View Documentation</span>
          </a>
        </div>
      </div>
    </div>

    <!-- Info Section -->
    <div class="grid lg:grid-cols-3 gap-8">
      <!-- Authentication Status -->
      <div class="glass rounded-xl p-6 shadow-lg">
        <div class="flex items-center gap-4 mb-6">
          <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center text-2xl">🔐</div>
          <h3 class="text-xl font-semibold text-slate-800">Authentication Status</h3>
        </div>
        <div class="space-y-4">
          <div v-if="isAuthenticated" class="inline-flex items-center gap-2 px-4 py-2 bg-green-100 text-green-700 rounded-lg text-sm font-medium border border-green-200">
            <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
            You are currently authenticated
          </div>
          <div v-else class="inline-flex items-center gap-2 px-4 py-2 bg-yellow-100 text-yellow-700 rounded-lg text-sm font-medium border border-yellow-200">
            <span class="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></span>
            You are not authenticated
          </div>
          <p class="text-slate-600 leading-relaxed">
            {{ isAuthenticated 
              ? 'You can access protected resources and view your profile.' 
              : 'Sign in to access protected resources and view your profile.' 
            }}
          </p>
        </div>
      </div>

      <!-- Configuration -->
      <div class="glass rounded-xl p-6 shadow-lg">
        <div class="flex items-center gap-4 mb-6">
          <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center text-2xl">⚙️</div>
          <h3 class="text-xl font-semibold text-slate-800">Configuration</h3>
        </div>
        <div class="space-y-4">
          <div class="flex justify-between items-center py-3 border-b border-slate-200">
            <strong class="text-slate-700">Authority:</strong>
            <code class="bg-slate-100 px-3 py-1 rounded-md text-sm text-blue-600 border">http://localhost:18888</code>
          </div>
          <div class="flex justify-between items-center py-3 border-b border-slate-200">
            <strong class="text-slate-700">Client ID:</strong>
            <code class="bg-slate-100 px-3 py-1 rounded-md text-sm text-blue-600 border">vue-demo-app</code>
          </div>
          <div class="flex justify-between items-center py-3">
            <strong class="text-slate-700">Redirect URI:</strong>
            <code class="bg-slate-100 px-3 py-1 rounded-md text-sm text-blue-600 border break-all">http://localhost:5173/callback</code>
          </div>
        </div>
      </div>

      <!-- Available Features -->
      <div class="glass rounded-xl p-6 shadow-lg">
        <div class="flex items-center gap-4 mb-6">
          <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center text-2xl">📋</div>
          <h3 class="text-xl font-semibold text-slate-800">Available Features</h3>
        </div>
        <div class="space-y-3">
          <div class="flex items-center gap-3 py-2 border-b border-slate-200">
            <span class="text-green-500 text-lg">✅</span>
            <span class="text-slate-700">Authorization Code Flow with PKCE</span>
          </div>
          <div class="flex items-center gap-3 py-2 border-b border-slate-200">
            <span class="text-green-500 text-lg">✅</span>
            <span class="text-slate-700">Refresh Token Support</span>
          </div>
          <div class="flex items-center gap-3 py-2 border-b border-slate-200">
            <span class="text-green-500 text-lg">✅</span>
            <span class="text-slate-700">OpenID Connect Discovery</span>
          </div>
          <div class="flex items-center gap-3 py-2 border-b border-slate-200">
            <span class="text-green-500 text-lg">✅</span>
            <span class="text-slate-700">JWT Token Validation</span>
          </div>
          <div class="flex items-center gap-3 py-2">
            <span class="text-green-500 text-lg">✅</span>
            <span class="text-slate-700">Logout/End Session</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Home-specific styles can be added here if needed */
</style>
