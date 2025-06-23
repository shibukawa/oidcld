<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { authService } from './authService';
import type { User } from 'oidc-client-ts';

const user = ref<User | null>(null);
const showRawData = ref(false);

const toggleRawData = () => {
  showRawData.value = !showRawData.value;
};

const formatDate = (timestamp: number | undefined): string => {
  if (!timestamp) return 'Unknown';
  return new Date(timestamp * 1000).toLocaleString();
};

const refreshToken = async () => {
  try {
    const refreshedUser = await authService.renewToken();
    if (refreshedUser) {
      user.value = refreshedUser;
    }
  } catch (error) {
    console.error('Token refresh failed:', error);
  }
};

onMounted(async () => {
  user.value = await authService.getUser();
});
</script>

<template>
  <div class="max-w-6xl mx-auto">
    <!-- Profile Header -->
    <div class="mb-8">
      <div class="glass rounded-2xl p-6 md:p-8 shadow-xl">
        <div class="flex flex-col md:flex-row items-center gap-6">
          <div class="flex-shrink-0">
            <div class="w-20 h-20 rounded-full bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center shadow-lg">
              <span class="text-3xl text-white">👤</span>
            </div>
          </div>
          
          <div class="flex-1 text-center md:text-left">
            <h1 class="text-3xl font-bold text-slate-800 mb-2">User Profile</h1>
            <div v-if="user" class="inline-flex items-center gap-2 px-4 py-2 bg-green-100 text-green-700 rounded-lg text-sm font-medium border border-green-200">
              <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
              Authenticated
            </div>
            <div v-else class="inline-flex items-center gap-2 px-4 py-2 bg-yellow-100 text-yellow-700 rounded-lg text-sm font-medium border border-yellow-200">
              <span class="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></span>
              Loading...
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="user" class="space-y-8">
      <div class="grid lg:grid-cols-2 gap-8">
        <!-- Basic Information -->
        <div class="glass rounded-xl p-6 shadow-lg">
          <div class="flex items-center justify-between mb-6">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center text-xl">ℹ️</div>
              <h2 class="text-xl font-semibold text-slate-800">Basic Information</h2>
            </div>
          </div>
          <div class="space-y-4">
            <div class="flex flex-col gap-2">
              <label class="text-sm font-semibold text-slate-600 uppercase tracking-wide">Display Name</label>
              <div class="text-slate-800 font-medium">{{ user.profile.name || 'Not provided' }}</div>
            </div>
            <div class="flex flex-col gap-2">
              <label class="text-sm font-semibold text-slate-600 uppercase tracking-wide">Email Address</label>
              <div class="text-slate-800 font-medium">{{ user.profile.email || 'Not provided' }}</div>
            </div>
            <div class="flex flex-col gap-2">
              <label class="text-sm font-semibold text-slate-600 uppercase tracking-wide">Subject ID</label>
              <code class="bg-slate-100 px-3 py-2 rounded-md text-sm text-blue-600 border font-mono break-all">{{ user.profile.sub }}</code>
            </div>
            <div class="flex flex-col gap-2">
              <label class="text-sm font-semibold text-slate-600 uppercase tracking-wide">Issuer</label>
              <code class="bg-slate-100 px-3 py-2 rounded-md text-sm text-blue-600 border font-mono break-all">{{ user.profile.iss }}</code>
            </div>
          </div>
        </div>

        <!-- Token Information -->
        <div class="glass rounded-xl p-6 shadow-lg">
          <div class="flex items-center gap-3 mb-6">
            <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center text-xl">🔑</div>
            <h2 class="text-xl font-semibold text-slate-800">Token Information</h2>
          </div>
          <div class="space-y-6">
            <div class="space-y-3">
              <label class="text-sm font-semibold text-slate-600 uppercase tracking-wide">Access Token</label>
              <div class="space-y-2">
                <div class="inline-flex items-center gap-2 px-3 py-1 bg-green-100 text-green-700 rounded-lg text-sm font-medium border border-green-200">
                  <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  Valid
                </div>
                <div class="text-sm text-slate-600">
                  Expires: {{ formatDate(user.expires_at) }}
                </div>
              </div>
            </div>
            <div v-if="user.refresh_token" class="space-y-3">
              <label class="text-sm font-semibold text-slate-600 uppercase tracking-wide">Refresh Token</label>
              <div class="inline-flex items-center gap-2 px-3 py-1 bg-green-100 text-green-700 rounded-lg text-sm font-medium border border-green-200">
                <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                Available
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="grid lg:grid-cols-2 gap-8">
        <!-- Scopes -->
        <div class="glass rounded-xl p-6 shadow-lg">
          <div class="flex items-center gap-3 mb-6">
            <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center text-xl">🔐</div>
            <h2 class="text-xl font-semibold text-slate-800">Granted Scopes</h2>
          </div>
          <div class="flex flex-wrap gap-2">
            <span 
              v-for="scope in user.scopes" 
              :key="scope" 
              class="bg-blue-100 text-blue-700 px-3 py-1 rounded-lg text-sm font-medium border border-blue-200"
            >
              {{ scope }}
            </span>
          </div>
        </div>

        <!-- Actions -->
        <div class="glass rounded-xl p-6 shadow-lg">
          <div class="flex items-center gap-3 mb-6">
            <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center text-xl">⚡</div>
            <h2 class="text-xl font-semibold text-slate-800">Actions</h2>
          </div>
          <div class="flex flex-col sm:flex-row gap-4">
            <button 
              @click="refreshToken" 
              :disabled="!user.refresh_token"
              class="btn-gradient text-white px-6 py-3 rounded-lg font-semibold flex items-center justify-center gap-2 hover:-translate-y-0.5 transition-all duration-200 shadow-md hover:shadow-lg disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              <span>🔄</span>
              Refresh Token
            </button>
            <button 
              @click="authService.logout" 
              class="bg-red-500 hover:bg-red-600 text-white px-6 py-3 rounded-lg font-semibold flex items-center justify-center gap-2 hover:-translate-y-0.5 transition-all duration-200 shadow-md hover:shadow-lg"
            >
              <span>👋</span>
              Sign Out
            </button>
          </div>
        </div>
      </div>

      <!-- Raw Token Data -->
      <div class="glass rounded-xl p-6 shadow-lg">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center text-xl">📄</div>
            <h2 class="text-xl font-semibold text-slate-800">Raw Token Data</h2>
          </div>
          <button 
            @click="toggleRawData" 
            class="bg-white border-2 border-blue-600 text-blue-600 hover:bg-blue-600 hover:text-white px-4 py-2 rounded-lg font-medium transition-all duration-200"
          >
            {{ showRawData ? 'Hide' : 'Show' }} Details
          </button>
        </div>
        <div v-if="showRawData" class="mt-6">
          <div class="bg-slate-900 text-slate-100 p-6 rounded-lg overflow-x-auto border">
            <pre class="text-sm font-mono whitespace-pre-wrap break-words"><code>{{ JSON.stringify(user, null, 2) }}</code></pre>
          </div>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-else class="flex justify-center items-center min-h-96">
      <div class="glass rounded-2xl p-12 text-center shadow-xl max-w-md w-full">
        <div class="flex flex-col items-center gap-6">
          <div class="w-16 h-16 border-4 border-slate-300 border-t-blue-600 rounded-full animate-spin"></div>
          <div>
            <h2 class="text-2xl font-bold text-slate-800 mb-2">Loading Profile...</h2>
            <p class="text-slate-600">Retrieving your authentication information</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Profile-specific styles can be added here if needed */
</style>