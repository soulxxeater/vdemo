module.exports = {
  root: true,
  env: {
    node: true
  },
  extends: [
    'plugin:vue/vue3-essential',
    'eslint:recommended'
  ],
  parserOptions: {
    parser: '@babel/eslint-parser'
  },
  rules: {
    // 忽略所有规则，因为我们主要处理第三方库文件
    'no-unused-vars': 'off',
    'no-undef': 'off',
    'no-redeclare': 'off',
    'no-empty': 'off',
    'no-cond-assign': 'off',
    'no-useless-escape': 'off',
    'no-prototype-builtins': 'off'
  },
  // 忽略特定目录和文件
  ignorePatterns: [
    'src/js/gdca-common.js',
    'src/js/cert_produce.js',
    'src/js/sync.js',
    'src/js/gdca-pki-service-min.js',
    'src/assets/jquery1.9.min.js',
    'src/utils/jquery1.9.min.js'
  ]
}