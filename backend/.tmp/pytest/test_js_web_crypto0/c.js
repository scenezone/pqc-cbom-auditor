const key = await crypto.subtle.generateKey({name: 'RSA-OAEP'}, true, ['encrypt','decrypt']);
