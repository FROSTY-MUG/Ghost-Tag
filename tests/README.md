# Ghost-Tag Global Testing & Code Analysis Utilities

## Overview
The `tests/` directory contains global static analysis utilities, dead-code scanners, and repository-wide test tooling for Ghost-Tag.

---

## Important Files

| File | Purpose | Environment |
| :--- | :--- | :--- |
| `scan-unused.cjs` | AST-based static analysis scanner detecting unreferenced exports, obsolete types, and dead modules across TypeScript sources. | Node.js CommonJS |

---

## How to Run

```bash
node tests/scan-unused.cjs
```

---

## Testing Architecture

Ghost-Tag employs a multi-tiered testing strategy:
1. **Unit & Integration Tests (`src/__tests__/`)**: Executed via Jest, covering cryptographic primitives, state machines, and vault management.
2. **Desktop Hardware Tests (`desktop/test/`)**: Executed via Node.js/Jest, covering PC/SC APDUs and PN532 serial protocol frames.
3. **Web Compatibility Tests (`src/__tests__/webSyntaxAndBuild.test.ts`)**: Executed via Jest, validating web scripts and Vite production bundling.
4. **Autonomous Audit Agents (`scripts/`)**: Executed via Python, enforcing zero-secrets, envelope invariants, and version synchronization.

---

## Contributor Guidelines

1. **Submitting Changes**:
   - Ensure all tests pass locally before pushing changes: `npm test && npm run audit`.
   - Run `node tests/scan-unused.cjs` to ensure newly added functions or files do not introduce dead exports.
