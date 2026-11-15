/**
 * @file RootNavigator.tsx
 * @summary Ghost-Tag Native Stack Navigator.
 *
 * Registers routes for Home, Single-Tag Read/Write, Bulk Vault Creation/Write/Scan,
 * Vault Reconstruction, Passphrase Management, and Security Defense Matrix.
 */

import React from 'react';
import { NavigationContainer, DefaultTheme } from '@react-navigation/native';
import {
  createNativeStackNavigator,
  type NativeStackScreenProps,
} from '@react-navigation/native-stack';
import {
  HomeScreen,
  ReadTagScreen,
  WriteTagScreen,
  BulkVaultCreationScreen,
  BulkWriteScreen,
  BulkScanScreen,
  ReconstructionScreen,
  PassphraseScreen,
  SettingsScreen,
} from '@ghost-tag/ui/screens';
import { theme } from '@ghost-tag/ui/theme';
import type { RootStackParamList } from './types';

const Stack = createNativeStackNavigator<RootStackParamList>();

const BulkWriteScreenWrapper: React.FC<NativeStackScreenProps<RootStackParamList, 'BulkWrite'>> = ({ route }) => (
  <BulkWriteScreen
    requiredTagCount={route.params?.requiredTagCount ?? 5}
    presentedTagCount={route.params?.presentedTagCount ?? 5}
  />
);

const BulkScanScreenWrapper: React.FC<NativeStackScreenProps<RootStackParamList, 'BulkScan'>> = ({ route }) => (
  <BulkScanScreen
    totalRequiredChunks={route.params?.totalRequiredChunks ?? 5}
  />
);

const ReconstructionScreenWrapper: React.FC<NativeStackScreenProps<RootStackParamList, 'Reconstruction'>> = () => (
  <ReconstructionScreen />
);

const GhostTheme = {
  ...DefaultTheme,
  dark: true,
  colors: {
    ...DefaultTheme.colors,
    primary: theme.colors.primary,
    background: theme.colors.background,
    card: theme.colors.surface,
    text: theme.colors.textPrimary,
    border: theme.colors.border,
    notification: theme.colors.accent,
  },
};

export const RootNavigator: React.FC = () => {
  return (
    <NavigationContainer theme={GhostTheme}>
      <Stack.Navigator
        initialRouteName="Home"
        screenOptions={{
          headerStyle: {
            backgroundColor: '#090b10',
          },
          headerTintColor: theme.colors.primary,
          headerTitleStyle: {
            fontWeight: '700',
            fontFamily: 'monospace',
            fontSize: 14,
          },
          contentStyle: {
            backgroundColor: theme.colors.background,
          },
        }}
      >
        <Stack.Screen
          name="Home"
          component={HomeScreen}
          options={{
            title: 'GHOST-TAG',
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="ReadTag"
          component={ReadTagScreen}
          options={{
            title: 'READ / SCAN TAG',
          }}
        />
        <Stack.Screen
          name="WriteTag"
          component={WriteTagScreen}
          options={{
            title: 'WRITE ENCRYPTED TAG',
          }}
        />
        <Stack.Screen
          name="BulkVaultCreation"
          component={BulkVaultCreationScreen}
          options={{
            title: 'CREATE DISTRIBUTED VAULT',
          }}
        />
        <Stack.Screen
          name="BulkWrite"
          component={BulkWriteScreenWrapper}
          options={{
            title: 'BULK WRITE TAGS',
          }}
        />
        <Stack.Screen
          name="BulkScan"
          component={BulkScanScreenWrapper}
          options={{
            title: 'BULK SCAN TAGS',
          }}
        />
        <Stack.Screen
          name="Reconstruction"
          component={ReconstructionScreenWrapper}
          options={{
            title: 'VAULT RECONSTRUCTION',
          }}
        />
        <Stack.Screen
          name="Passphrase"
          component={PassphraseScreen}
          options={{
            title: 'PASSPHRASE & RECOVERY',
          }}
        />
        <Stack.Screen
          name="Settings"
          component={SettingsScreen}
          options={{
            title: 'SECURITY & SETTINGS',
          }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
};
