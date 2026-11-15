import type { NativeStackNavigationProp } from '@react-navigation/native-stack';

export type RootStackParamList = {
  Home: undefined;
  ReadTag: undefined;
  WriteTag: undefined;
  BulkVaultCreation: undefined;
  BulkWrite: { requiredTagCount?: number; presentedTagCount?: number };
  BulkScan: { totalRequiredChunks?: number };
  Reconstruction: { targetFileCount?: number };
  Passphrase: undefined;
  Settings: undefined;
};

export type HomeScreenNavigationProp = NativeStackNavigationProp<
  RootStackParamList,
  'Home'
>;
