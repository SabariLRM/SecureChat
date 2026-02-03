const crypto = require('crypto');

// Copy-paste form server.js
function generateUserKeys() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
}

function encryptPrivateKey(privateKey, password) {
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return { content: encrypted, iv: iv.toString('hex'), tag: tag.toString('hex') };
}

function decryptPrivateKey(encryptedObj, password) {
    const { content, iv, tag } = JSON.parse(encryptedObj);
    const key = crypto.scryptSync(password, 'salt', 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decrypted = decipher.update(content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Test
try {
    console.log("Generating keys...");
    const { publicKey, privateKey } = generateUserKeys();
    console.log("Original Private Key starts with:", privateKey.substring(0, 30));

    const password = "testpassword123";
    console.log("Encrypting...");
    const encrypted = JSON.stringify(encryptPrivateKey(privateKey, password));

    console.log("Decrypting...");
    const decrypted = decryptPrivateKey(encrypted, password);

    console.log("Decrypted Private Key starts with:", decrypted.substring(0, 30));

    if (privateKey === decrypted) {
        console.log("SUCCESS: Keys match exactly.");
        if (decrypted.includes("BEGIN PRIVATE KEY")) {
            console.log("SUCCESS: Format looks like PKCS8 PEM.");
        } else {
            console.error("FAILURE: Format lost header?");
        }
    } else {
        console.error("FAILURE: Keys mismatch!");
    }

} catch (e) {
    console.error("CRASH:", e);
}
