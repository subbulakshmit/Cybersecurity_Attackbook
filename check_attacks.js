const fs = require('fs');
const content = fs.readFileSync('app.js', 'utf8');
const regex = /num:\s*(\d+),\s*id:\s*["']([^"']+)["'],\s*name:\s*["']([^"']+)["'],\s*shortName:\s*["']([^"']+)["'],\s*moduleGroup:\s*["']([^"']+)["']/g;
let match;
while ((match = regex.exec(content)) !== null) {
  console.log(`${match[1].padStart(3, '0')}. [${match[5]}] ${match[3]} (id: ${match[2]})`);
}
