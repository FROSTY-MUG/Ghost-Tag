/**
 * @file App.test.tsx
 * @summary Root App rendering and stack initialization test.
 */

import React from 'react';
import ReactTestRenderer from 'react-test-renderer';
import App from '../../App';

test('renders correctly', async () => {
  await ReactTestRenderer.act(() => {
    ReactTestRenderer.create(<App />);
  });
});
