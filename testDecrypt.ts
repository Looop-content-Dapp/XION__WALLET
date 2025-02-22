// testDecrypt.ts
const nodeCrypto = require('crypto');

const serverSecret = '3f6ecf4bb56bce856690bea8ac95889f450fbf48dd3f6eab1c978b6f0e241542';
const password = 'PurpleRain1984!';
const mnemonic = 'melody rhythm beat tune chord note song lyric riff bass drum piano'; // Example
const salt = nodeCrypto.randomBytes(16);
const key = nodeCrypto.pbkdf2Sync(password + serverSecret, salt, 100000, 32, 'sha256');
const iv = nodeCrypto.randomBytes(16);
const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
let encrypted = cipher.update(mnemonic, 'utf8', 'hex');
encrypted += cipher.final('hex');

console.log('Encrypted:', encrypted);
console.log('IV:', iv.toString('hex'));
console.log('Salt:', salt.toString('hex'));

const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
let decrypted = decipher.update(encrypted, 'hex', 'utf8');
decrypted += decipher.final('utf8');
console.log('Decrypted:', decrypted);