/**
 * @file index.js
 * @description Entry point for Ghost Bridge desktop service
 */

const { GhostBridgeServer, PORT, HOST } = require('./server');

function startBridge() {
  const bridge = new GhostBridgeServer();
  bridge.start();

  process.on('SIGINT', () => {
    console.log('\n[Ghost Bridge] Shutting down gracefully...');
    bridge.stop();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    bridge.stop();
    process.exit(0);
  });

  return bridge;
}

module.exports = {
  GhostBridgeServer,
  startBridge,
  PORT,
  HOST
};

if (require.main === module) {
  startBridge();
}
