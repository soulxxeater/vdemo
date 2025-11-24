const { defineConfig } = require('@vue/cli-service')
module.exports = defineConfig({
  transpileDependencies: true,
  devServer: {
    port: 8082,
    proxy: {
      '/gdca_ws_v2': {
        target: 'ws://127.0.0.1:55663',
        ws: true,
        changeOrigin: true
      }
    }
  }
})