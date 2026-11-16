module.exports = {
  root: true,
  extends: '@react-native',
  ignorePatterns: [
    'dist/',
    'node_modules/',
    'android/',
    'ios/',
    'coverage/',
    'web/',
    'desktop/',
    'scripts/',
    'supabase/',
  ],
  rules: {
    '@typescript-eslint/no-unused-vars': [
      'warn',
      {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^_',
      },
    ],
    'no-bitwise': 'off',
  },
};
