/**
 * @file index.ts
 * @summary Ghost-Tag NFC Hardware Abstraction Layer Barrel Export.
 *
 * Exports NFC lifecycle management, foreground dispatch, NDEF reading and construction,
 * verified writing, destructive sanitization, hardware capability inspection,
 * and error mapping.
 */

export * from './nfcManager';
export * from './tagReader';
export * from './tagWriter';
export * from './tagInfo';
export * from './tagWiper';
export * from './ndefBuilder';
export * from './errors';
