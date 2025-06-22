<script setup lang="ts">
import { onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { authService } from './authService';

const router = useRouter();

onMounted(async () => {
  try {
    await authService.handleCallback();
    router.push('/');
  } catch (error) {
    console.error('Callback Error:', error);
    router.push('/');
  }
});
</script>

<template>
  <div class="min-h-screen flex items-center justify-center p-8">
    <div class="w-full max-w-lg">
      <div class="glass rounded-2xl p-12 text-center shadow-2xl">
        <div class="flex flex-col items-center gap-8">
          <div class="flex items-center justify-center">
            <div class="w-16 h-16 border-4 border-slate-300 border-t-blue-600 rounded-full animate-spin"></div>
          </div>
          
          <div class="text-center">
            <h1 class="text-3xl font-bold mb-4 gradient-text">
              Processing Authentication
            </h1>
            <p class="text-xl text-slate-600 leading-relaxed">
              Please wait while we complete your authentication process...
            </p>
          </div>
          
          <div class="w-full space-y-6">
            <div class="w-full bg-slate-200 rounded-full h-1 overflow-hidden">
              <div class="h-full bg-gradient-to-r from-blue-600 to-purple-600 rounded-full animate-pulse" 
                  style="animation: progress 3s ease-in-out infinite;"></div>
            </div>
            
            <div class="flex justify-between items-center text-sm">
              <div class="flex flex-col items-center gap-2 flex-1 relative">
                <div class="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-semibold text-sm animate-pulse">
                  1
                </div>
                <span class="text-blue-600 font-semibold">Validating</span>
              </div>
              <div class="flex-1 h-0.5 bg-blue-600 mx-2"></div>
              <div class="flex flex-col items-center gap-2 flex-1 relative">
                <div class="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-semibold text-sm animate-pulse">
                  2
                </div>
                <span class="text-blue-600 font-semibold">Processing</span>
              </div>
              <div class="flex-1 h-0.5 bg-slate-300 mx-2"></div>
              <div class="flex flex-col items-center gap-2 flex-1 relative">
                <div class="w-8 h-8 rounded-full bg-slate-300 text-slate-500 flex items-center justify-center font-semibold text-sm">
                  3
                </div>
                <span class="text-slate-500 font-medium">Complete</span>
              </div>
            </div>
          </div>
          
          <div class="mt-4">
            <p class="text-sm text-slate-500 italic">
              If this process takes longer than expected, please check your network connection.
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
@keyframes progress {
  0% { width: 0%; }
  50% { width: 70%; }
  100% { width: 100%; }
}
</style>
