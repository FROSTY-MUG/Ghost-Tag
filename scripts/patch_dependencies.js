#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const targets = [
  path.join(__dirname, '..', 'node_modules', 'react-native-argon2', 'android', 'build.gradle'),
];

for (const target of targets) {
  try {
    const content = fs.readFileSync(target, 'utf8');
    if (content.includes('jcenter()')) {
      const patched = content.replace(/jcenter\(\)/g, 'mavenCentral()');
      const tempPath = `${target}.${process.pid}.tmp`;
      fs.writeFileSync(tempPath, patched, 'utf8');
      fs.renameSync(tempPath, target);
      console.log(`[patch] Atomically replaced deprecated jcenter() with mavenCentral() in ${target}`);
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.warn(`[patch] Notice: ${target} not modified:`, err.message);
    }
  }
}
