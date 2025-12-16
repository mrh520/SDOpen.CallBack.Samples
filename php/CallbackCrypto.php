<?php

class CallbackCrypto {
    const RANDOM_LENGTH = 16;
    private $_aesKey;
    private $_clientId;

    public function __construct($encodingAesKey, $clientId) {
        if (empty($encodingAesKey)) {
            throw new Exception('Encryption key cannot be empty');
        }
        $this->_aesKey = base64_decode($encodingAesKey);
        if (strlen($this->_aesKey) !== 16) {
            throw new Exception("Invalid AES key length: expected 16 bytes, got " . strlen($this->_aesKey) . " bytes");
        }
        $this->_clientId = $clientId;
    }

    public function getEncryptedMap($plaintext, $timestamp = null) {
        if (empty($plaintext)) {
            throw new Exception('Plaintext cannot be empty');
        }
        $timestamp = $timestamp ?? time() * 1000; // 毫秒时间戳
        $nonce = Utils::getRandomStr(self::RANDOM_LENGTH);
        $encrypt = $this->encrypt($nonce, $plaintext);
        $signature = $this->getSignature((string)$timestamp, $nonce, $encrypt);

        return [
            'signature' => $signature,
            'encrypt' => $encrypt,
            'timestamp' => (string)$timestamp,
            'nonce' => $nonce
        ];
    }

    public function getDecryptMsg($msgSignature, $timestamp, $nonce, $encryptMsg) {
        $signature = $this->getSignature($timestamp, $nonce, $encryptMsg);
        if ($signature !== $msgSignature) {
            throw new Exception('Signature mismatch');
        }
        return $this->decrypt($encryptMsg);
    }

    private function encrypt($nonce, $plaintext) {
        $randomBytes = $nonce;
        $plainTextBytes = $plaintext;
        $lengthBytes = Utils::int2Bytes(strlen($plainTextBytes));
        $clientIdBytes = $this->_clientId;

        $data = $randomBytes . $lengthBytes . $plainTextBytes . $clientIdBytes;
        $paddedData = PKCS7Padding::getPaddingBytes($data);

        $iv = substr($this->_aesKey, 0, 16);
        $encrypted = openssl_encrypt(
            $paddedData,
            'aes-128-cbc',
            $this->_aesKey,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $iv
        );

        return base64_encode($encrypted);
    }

    private function decrypt($text) {
        $cipherText = base64_decode($text);
        $iv = substr($this->_aesKey, 0, 16);
        $decrypted = openssl_decrypt(
            $cipherText,
            'aes-128-cbc',
            $this->_aesKey,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $iv
        );

        $unpadded = PKCS7Padding::removePaddingBytes($decrypted);
        $plainTextLength = Utils::bytes2Int(substr($unpadded, self::RANDOM_LENGTH, 4));
        $plaintext = substr($unpadded, self::RANDOM_LENGTH + 4, $plainTextLength);
        $msgClientId = substr($unpadded, self::RANDOM_LENGTH + 4 + $plainTextLength);

        if ($msgClientId !== $this->_clientId) {
            throw new Exception('ClientID mismatch in decrypted message');
        }
        return $plaintext;
    }

    private function getSignature($timestamp, $nonce, $encrypt) {
        $array = [$this->_clientId, $timestamp, $nonce, $encrypt];
        sort($array, SORT_STRING);
        $data = implode('', $array);
        return sha1($data);
    }
}

class Utils {
    public static function getRandomStr($count) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $result = '';
        for ($i = 0; $i < $count; $i++) {
            $result .= $chars[mt_rand(0, strlen($chars) - 1)];
        }
        return $result;
    }

    public static function int2Bytes($number) {
        $buffer = pack('N', $number); // 32位大端字节序
        return $buffer;
    }

    public static function bytes2Int($byteArr) {
        $unpacked = unpack('N', $byteArr); // 32位大端字节序解析
        return $unpacked[1];
    }
}

class PKCS7Padding {
    const BLOCK_SIZE = 32;

    public static function getPaddingBytes($data) {
        $dataLen = strlen($data);
        $amountToPad = self::BLOCK_SIZE - ($dataLen % self::BLOCK_SIZE);
        if ($amountToPad === 0) {
            $amountToPad = self::BLOCK_SIZE;
        }
        $padChr = chr($amountToPad);
        return $data . str_repeat($padChr, $amountToPad);
    }

    public static function removePaddingBytes($decrypted) {
        $pad = ord(substr($decrypted, -1));
        if ($pad < 1 || $pad > self::BLOCK_SIZE) {
            return $decrypted;
        }
        return substr($decrypted, 0, strlen($decrypted) - $pad);
    }
}