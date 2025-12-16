<?php
require_once 'CallbackCrypto.php';

$encodingAesKey = 'nMM/aZcZVw7NVm//n+9pGg==';
$clientId = 'appId';

// 初始化CallbackCrypto
try {
    $crypto = new CallbackCrypto($encodingAesKey, $clientId);
} catch (Exception $e) {
    error_log("Failed to initialize CallbackCrypto: " . $e->getMessage());
    exit(1);
}

$plaintext = 'hello, SDOpen!';
echo "Plaintext: {$plaintext}\n";

// 加密消息
try {
    $timestamp = time() * 1000; // 毫秒时间戳
    echo "Timestamp: {$timestamp}\n";
    $encryptedMap = $crypto->getEncryptedMap($plaintext, $timestamp);
    echo "Encrypted Map:\n";
    echo "Signature: {$encryptedMap['signature']}\n";
    echo "Encrypt: {$encryptedMap['encrypt']}\n";
    echo "Timestamp: {$encryptedMap['timestamp']}\n";
    echo "Nonce: {$encryptedMap['nonce']}\n";
} catch (Exception $e) {
    error_log("Encryption failed: " . $e->getMessage());
    exit(1);
}

// 解密消息
try {
    $decrypted = $crypto->getDecryptMsg(
        $encryptedMap['signature'],
        $encryptedMap['timestamp'],
        $encryptedMap['nonce'],
        $encryptedMap['encrypt']
    );
    echo "\nDecrypted Message: {$decrypted}\n";
    if ($decrypted !== $plaintext) {
        error_log("Error: Decrypted message does not match original plaintext");
    }
} catch (Exception $e) {
    error_log("Decryption failed: " . $e->getMessage());
    exit(1);
}
