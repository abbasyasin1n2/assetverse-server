// Run: node encode.js
// Outputs base64 of your firebase admin key for Vercel env (FB_SERVICE_KEY)
const fs = require('fs');

const keyPath = './assestverse-clientside-firebase-adminsdk-serviceAccountKey.json';
const key = fs.readFileSync(keyPath, 'utf8');
const base64 = Buffer.from(key).toString('base64');

console.log(base64);
