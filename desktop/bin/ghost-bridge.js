#!/usr/bin/env node

/**
 * @file ghost-bridge.js
 * @description CLI launcher for Ghost Bridge USB NFC companion
 */

const { startBridge } = require('../src/index');

console.log('======================================================');
console.log(' Ghost Bridge v2.0.5 — USB NFC Hardware Companion');
console.log(' Enabling real ACR122U NFC readers on laptops');
console.log('======================================================');

startBridge();
