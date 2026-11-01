const ciphertext = CryptoJS.AES.encrypt('my message', 'secret key 123');
const token = jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256' });
