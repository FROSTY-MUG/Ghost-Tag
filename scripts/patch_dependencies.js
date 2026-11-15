#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const targets = [
  path.join(__dirname, '..', 'node_modules', 'react-native-argon2', 'android', 'build.gradle'),
];

for (const target of targets) {
  if (fs.existsSync(target)) {
    let content = fs.readFileSync(target, 'utf8');
    if (content.includes('jcenter()')) {
      content = content.replace(/jcenter\(\)/g, 'mavenCentral()');
      fs.writeFileSync(target, content, 'utf8');
      console.log(`[patch] Replaced deprecated jcenter() with mavenCentral() in ${target}`);
    }
  }
}
