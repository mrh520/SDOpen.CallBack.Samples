const { CallbackCrypto } = require('./callbackCrypto');

const encodingAesKey = 'nMM/aZcZVw7NVm//n+9pGg==';
const clientId = 'appId';

// Initialize CallbackCrypto
let crypto;
try {
    crypto = new CallbackCrypto(encodingAesKey, clientId);
} catch (err) {
    console.error(`Failed to initialize CallbackCrypto: ${err.message}`);
    process.exit(1);
}

const plaintext = 'hello, SDOpen!';
console.log(`Plaintext: ${plaintext}`);

// Encrypt the message
let encryptedMap;
try {
    const timestamp = Date.now();
    console.log(`Timestamp: ${timestamp}`);
    encryptedMap = crypto.getEncryptedMap(plaintext, timestamp);
    console.log('Encrypted Map:');
    console.log(`Signature: ${encryptedMap.signature}`);
    console.log(`Encrypt: ${encryptedMap.encrypt}`);
    console.log(`Timestamp: ${encryptedMap.timestamp}`);
    console.log(`Nonce: ${encryptedMap.nonce}`);
} catch (err) {
    console.error(`Encryption failed: ${err.message}`);
    process.exit(1);
}

// Decrypt the message
try {
    const decrypted = crypto.getDecryptMsg(
        encryptedMap.signature,
        encryptedMap.timestamp,
        encryptedMap.nonce,
        encryptedMap.encrypt
    );
    console.log(`\nDecrypted Message: ${decrypted}`);
    if (decrypted !== plaintext) {
        console.error('Error: Decrypted message does not match original plaintext');
    }
} catch (err) {
    console.error(`Decryption failed: ${err.message}`);
    process.exit(1);
}