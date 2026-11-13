import { Buffer } from 'buffer';

const globalObj = globalThis as unknown as { Buffer: typeof Buffer };

if (!globalObj.Buffer) {
  globalObj.Buffer = Buffer;
}

export { Buffer };
