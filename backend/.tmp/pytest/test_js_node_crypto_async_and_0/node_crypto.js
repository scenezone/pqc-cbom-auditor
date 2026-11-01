const crypto = require('crypto');
crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => {});
const hmac = crypto.createHmac('sha256', secret);
