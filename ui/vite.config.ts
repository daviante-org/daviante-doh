import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    sourcemap: false,
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('@patternfly/react-table')) {
              return 'patternfly-table';
            }
            if (id.includes('@patternfly')) {
              return 'patternfly-core';
            }
            if (id.includes('zod') || id.includes('react-hook-form') || id.includes('@hookform')) {
              return 'validation';
            }
            if (id.includes('react') || id.includes('scheduler')) {
              return 'react-vendor';
            }
          }
          return undefined;
        }
      }
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/api/v1': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: false
      }
    }
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/testSetup.ts']
  }
});
