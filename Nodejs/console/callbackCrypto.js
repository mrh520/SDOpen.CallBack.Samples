const crypto = require('crypto');

class CallbackCrypto {
    static RANDOM_LENGTH = 16;

    constructor(encodingAesKey, clientId) {
        if (!encodingAesKey) {
            throw new Error('Encryption key cannot be empty');
        }
        this._aesKey = Buffer.from(encodingAesKey, 'base64');
        if (this._aesKey.length !== 16) {
            throw new Error(`Invalid AES key length: expected 16 bytes, got ${this._aesKey.length} bytes`);
        }
        this._clientId = clientId;
    }

    getEncryptedMap(plaintext, timestamp = Date.now()) {
        if (!plaintext) {
            throw new Error('Plaintext cannot be empty');
        }
        const nonce = Utils.getRandomStr(CallbackCrypto.RANDOM_LENGTH);
        const encrypt = this.encrypt(nonce, plaintext);
        const signature = this.getSignature(timestamp.toString(), nonce, encrypt);

        return {
            signature,
            encrypt,
            timestamp: timestamp.toString(),
            nonce
        };
    }

    getDecryptMsg(msgSignature, timestamp, nonce, encryptMsg) {
        const signature = this.getSignature(timestamp, nonce, encryptMsg);
        if (signature !== msgSignature) {
            throw new Error('Signature mismatch');
        }
        return this.decrypt(encryptMsg);
    }

    encrypt(nonce, plaintext) {
        const randomBytes = Buffer.from(nonce, 'utf8');
        const plainTextBytes = Buffer.from(plaintext, 'utf8');
        const lengthBytes = Utils.int2Bytes(plainTextBytes.length);
        const clientIdBytes = Buffer.from(this._clientId, 'utf8');

        let data = Buffer.concat([randomBytes, lengthBytes, plainTextBytes, clientIdBytes]);
        const paddedData = PKCS7Padding.getPaddingBytes(data);

        const cipher = crypto.createCipheriv('aes-128-cbc', this._aesKey, this._aesKey.slice(0, 16));
        cipher.setAutoPadding(false);
        let encrypted = cipher.update(paddedData);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        return encrypted.toString('base64');
    }

    decrypt(text) {
        const decipher = crypto.createDecipheriv('aes-128-cbc', this._aesKey, this._aesKey.slice(0, 16));
        decipher.setAutoPadding(false);
        let decrypted = decipher.update(Buffer.from(text, 'base64'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        const unpadded = PKCS7Padding.removePaddingBytes(decrypted);
        const plainTextLength = Utils.bytes2Int(unpadded.slice(CallbackCrypto.RANDOM_LENGTH, CallbackCrypto.RANDOM_LENGTH + 4));
        const plaintext = unpadded.slice(CallbackCrypto.RANDOM_LENGTH + 4, CallbackCrypto.RANDOM_LENGTH + 4 + plainTextLength).toString('utf8');
        const msgClientId = unpadded.slice(CallbackCrypto.RANDOM_LENGTH + 4 + plainTextLength).toString('utf8');

        if (msgClientId !== this._clientId) {
            throw new Error('ClientID mismatch in decrypted message');
        }
        return plaintext;
    }

    getSignature(timestamp, nonce, encrypt) {
        const array = [this._clientId, timestamp, nonce, encrypt];
        array.sort();
        const data = array.join('');
        return crypto.createHash('sha1').update(data, 'ascii').digest('hex');
    }
}

class Utils {
    static getRandomStr(count) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < count; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    static int2Bytes(number) {
        const buffer = Buffer.alloc(4);
        buffer.writeInt32BE(number, 0);
        return buffer;
    }

    static bytes2Int(byteArr) {
        return byteArr.readInt32BE(0);
    }
}

class PKCS7Padding {
    static BLOCK_SIZE = 32;

    static getPaddingBytes(data) {
        const amountToPad = this.BLOCK_SIZE - (data.length % this.BLOCK_SIZE) || this.BLOCK_SIZE;
        const padChr = String.fromCharCode(amountToPad);
        return Buffer.concat([data, Buffer.alloc(amountToPad, padChr)]);
    }

    static removePaddingBytes(decrypted) {
        const pad = decrypted[decrypted.length - 1];
        if (pad < 1 || pad > this.BLOCK_SIZE) {
            return decrypted;
        }
        return decrypted.slice(0, decrypted.length - pad);
    }
}

module.exports = { CallbackCrypto, Utils, PKCS7Padding };