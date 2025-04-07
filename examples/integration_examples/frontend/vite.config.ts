import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/aggregator1/v1': {
        target: 'https://aggregator.walrus-testnet.walrus.space',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/aggregator/, ''),
      },
      '/aggregator2/v1': {
        target: 'https://wal-aggregator-testnet.staketab.org',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/aggregator2/, ''),
      },
      '/aggregator3/v1': {
        target: 'https://walrus-testnet-aggregator.redundex.com',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/aggregator3/, ''),
      },
      '/aggregator4/v1': {
        target: 'https://walrus-testnet-aggregator.trusted-point.com',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/aggregator3/, ''),
      },
      '/publisher1/v1': {
        target: 'https://publisher.walrus-testnet.walrus.space',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/publisher1/, ''),
      },
      '/publisher2/v1': {
        target: 'https://wal-publisher-testnet.staketab.org',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/publisher2/, ''),
      },
      '/publisher3/v1': {
        target: 'https://walrus-testnet-publisher.redundex.com',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/publisher3/, ''),
      },
      '/publisher4/v1': {
        target: 'https://walrus-testnet-publisher.trusted-point.com',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/publisher3/, ''),
      },
    },
  },
});
