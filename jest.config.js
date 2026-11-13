module.exports = {
  preset: '@react-native/jest-preset',
  transformIgnorePatterns: [
    'node_modules/(?!(@react-native|react-native|@react-navigation|react-native-mmkv)/)',
  ],
  moduleNameMapper: {
    '^@ghost-tag/(.*)$': '<rootDir>/src/$1',
    '^react-native-quick-crypto$': '<rootDir>/node_modules/react-native-quick-crypto/jest',
  },
};
