import base64
import hashlib
import random
import string
from Crypto.Cipher import AES
import time


class CallbackCrypto:
    RANDOM_LENGTH = 16

    def __init__(self, encoding_aes_key, client_id):
        if not encoding_aes_key:
            raise ValueError("Encryption key cannot be empty")

        # 解码Base64密钥并验证长度
        self._aes_key = base64.b64decode(encoding_aes_key)
        if len(self._aes_key) != 16:
            raise ValueError(
                f"Invalid AES key length: expected 16 bytes, got {len(self._aes_key)} bytes"
            )

        self._client_id = client_id

    def get_encrypted_map(self, plaintext, timestamp=None):
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")

        timestamp = timestamp or str(int(time.time() * 1000))
        nonce = Utils.get_random_str(CallbackCrypto.RANDOM_LENGTH)
        encrypt = self.encrypt(nonce, plaintext)
        signature = self.get_signature(timestamp, nonce, encrypt)

        return {
            "signature": signature,
            "encrypt": encrypt,
            "timestamp": timestamp,
            "nonce": nonce,
        }

    def get_decrypt_msg(self, msg_signature, timestamp, nonce, encrypt_msg):
        signature = self.get_signature(timestamp, nonce, encrypt_msg)
        if signature != msg_signature:
            raise ValueError("Signature mismatch")
        return self.decrypt(encrypt_msg)

    def encrypt(self, nonce, plaintext):
        # 构建数据结构: 随机串 + 内容长度(4字节) + 明文 + client_id
        random_bytes = nonce.encode("utf-8")
        plaintext_bytes = plaintext.encode("utf-8")
        length_bytes = Utils.int_to_bytes(len(plaintext_bytes))
        client_id_bytes = self._client_id.encode("utf-8")

        data = random_bytes + length_bytes + plaintext_bytes + client_id_bytes
        padded_data = PKCS7Padding.get_padding_bytes(data)

        # AES-CBC加密
        cipher = AES.new(self._aes_key, AES.MODE_CBC, self._aes_key[:16])
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt(self, text):
        # 解密过程
        encrypted_data = base64.b64decode(text)
        decipher = AES.new(self._aes_key, AES.MODE_CBC, self._aes_key[:16])
        decrypted = decipher.decrypt(encrypted_data)

        # 去除填充
        unpadded = PKCS7Padding.remove_padding_bytes(decrypted)

        # 解析数据结构
        random_length = CallbackCrypto.RANDOM_LENGTH
        length_bytes = unpadded[random_length : random_length + 4]
        plaintext_length = Utils.bytes_to_int(length_bytes)

        plaintext = unpadded[
            random_length + 4 : random_length + 4 + plaintext_length
        ].decode("utf-8")
        msg_client_id = unpadded[random_length + 4 + plaintext_length :].decode("utf-8")

        if msg_client_id != self._client_id:
            raise ValueError("ClientID mismatch in decrypted message")

        return plaintext

    def get_signature(self, timestamp, nonce, encrypt):
        # 生成签名
        array = [self._client_id, timestamp, nonce, encrypt]
        array.sort()
        data = "".join(array)
        sha1 = hashlib.sha1()
        sha1.update(data.encode("ascii"))
        return sha1.hexdigest()

    def verify_signature(self, signature, timestamp, nonce, encrypt):
        return signature == self.get_signature(str(timestamp) , nonce, encrypt)


class Utils:
    @staticmethod
    def get_random_str(count):
        # 生成指定长度的随机字符串
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(count))

    @staticmethod
    def int_to_bytes(number):
        # 整数转4字节大端序
        return number.to_bytes(4, byteorder="big", signed=False)

    @staticmethod
    def bytes_to_int(byte_arr):
        # 4字节大端序转整数
        return int.from_bytes(byte_arr, byteorder="big", signed=False)


class PKCS7Padding:
    BLOCK_SIZE = 32

    @staticmethod
    def get_padding_bytes(data):
        # 计算填充长度
        amount_to_pad = PKCS7Padding.BLOCK_SIZE - (len(data) % PKCS7Padding.BLOCK_SIZE)
        if amount_to_pad == 0:
            amount_to_pad = PKCS7Padding.BLOCK_SIZE

        # 生成填充字节
        pad_byte = bytes([amount_to_pad])
        return data + pad_byte * amount_to_pad

    @staticmethod
    def remove_padding_bytes(decrypted):
        # 去除填充
        if not decrypted:
            return decrypted

        pad = decrypted[-1]
        if 1 <= pad <= PKCS7Padding.BLOCK_SIZE:
            return decrypted[:-pad]
        return decrypted


# 需要安装pycryptodome库
# 安装命令: pip install pycryptodome
