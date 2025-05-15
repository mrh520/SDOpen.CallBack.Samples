package com.yinxq.demo.util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.*;

/**
 * 开放平台加解密方法
 */
public class CallbackCrypto {

    private static final Charset CHARSET = Charset.forName("utf-8");
    final Base64.Decoder decoder = Base64.getDecoder();
    final Base64.Encoder encoder = Base64.getEncoder();
    private byte[] aesKey;
    private String clientId;
    private static final Integer AES_ENCODE_KEY_LENGTH = 24;
    // 随机字符串字节长度
    private static final Integer RANDOM_LENGTH = 16;

    /**
     * 构造函数
     *
     * @param encodingAesKey 开放平台上，开发者设置的EncodingAESKey
     * @param clientId       开放平台上，应用的clientId
     *
     * @throws CallbackCryptoException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public CallbackCrypto(String encodingAesKey, String clientId) throws CallbackCryptoException {
        if (null == encodingAesKey || encodingAesKey.length() != AES_ENCODE_KEY_LENGTH) {
            throw new CallbackCryptoException(CallbackCryptoException.AES_KEY_ILLEGAL);
        }
        this.clientId = clientId;
        aesKey = decoder.decode(encodingAesKey);
    }

    /**
     * 将和开放平台同步的消息体加密,返回加密Map
     *
     * @param plaintext 传递的消息体明文
     */
    public Map<String, String> getEncryptedMap(String plaintext) throws CallbackCryptoException {
        return getEncryptedMap(plaintext, System.currentTimeMillis());
    }

    /**
     * 将和开放平台同步的消息体加密,返回加密Map
     *
     * @param plaintext 传递的消息体明文
     * @param timestamp 时间戳
     * @return
     * @throws CallbackCryptoException
     */
    public Map<String, String> getEncryptedMap(String plaintext, Long timestamp)
            throws CallbackCryptoException {
        if (null == plaintext) {
            throw new CallbackCryptoException(CallbackCryptoException.ENCRYPTION_PLAINTEXT_ILLEGAL);
        }

        // 加密
        String nonce = Utils.getRandomStr(RANDOM_LENGTH);
        String encrypt = encrypt(nonce, plaintext);
        String signature = getSignature(String.valueOf(timestamp), nonce, encrypt);

        Map<String, String> resultMap = new HashMap<String, String>();
        resultMap.put("signature", signature);
        resultMap.put("encrypt", encrypt);
        resultMap.put("timestamp", String.valueOf(timestamp));
        resultMap.put("nonce", nonce);
        return resultMap;
    }

    /**
     * 密文解密
     *
     * @param msgSignature 签名串
     * @param timestamp    时间戳
     * @param nonce        随机串
     * @param encryptMsg   密文
     * @return 解密后的原文
     * @throws CallbackCryptoException
     */
    public String getDecryptMsg(String msgSignature, String timestamp, String nonce, String encryptMsg)
            throws CallbackCryptoException {
        // 校验签名
        String signature = getSignature(timestamp, nonce, encryptMsg);
        if (!signature.equals(msgSignature)) {
            throw new CallbackCryptoException(CallbackCryptoException.SIGNATURE_NOT_MATCH);
        }

        // 解密
        return decrypt(encryptMsg);
    }

    /**
     * 对明文加密
     *
     * @param nonce     随机串
     * @param plaintext 需要加密的明文
     * @return 加密后base64编码的字符串
     * @throws CallbackCryptoException
     */
    private String encrypt(String nonce, String plaintext) throws CallbackCryptoException {
        try {
            byte[] randomBytes = nonce.getBytes(CHARSET);
            byte[] plainTextBytes = plaintext.getBytes(CHARSET);
            byte[] lengthByte = Utils.int2Bytes(plainTextBytes.length);
            byte[] corpidBytes = clientId.getBytes(CHARSET);
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            byteStream.write(randomBytes);
            byteStream.write(lengthByte);
            byteStream.write(plainTextBytes);
            byteStream.write(corpidBytes);
            byte[] padBytes = PKCS7Padding.getPaddingBytes(byteStream.size());
            byteStream.write(padBytes);
            byte[] unencrypted = byteStream.toByteArray();
            byteStream.close();

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(aesKey, 0, 16);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            byte[] encrypted = cipher.doFinal(unencrypted);

            return encoder.encodeToString(encrypted);
        } catch (Exception e) {
            // System.err.println(e);
            throw new CallbackCryptoException(CallbackCryptoException.COMPUTE_ENCRYPT_TEXT_ERROR);
        }
    }

    /**
     * 对密文进行解密
     *
     * @param text 需要解密的密文
     * @return 解密得到的明文
     */
    private String decrypt(String text) throws CallbackCryptoException {
        byte[] originalArr;
        try {
            // 设置解密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
            // 使用BASE64对密文进行解码
            byte[] encrypted = decoder.decode(text);
            // 解密
            originalArr = cipher.doFinal(encrypted);
        } catch (Exception e) {
            throw new CallbackCryptoException(CallbackCryptoException.COMPUTE_DECRYPT_TEXT_ERROR);
        }

        String plaintext;
        String msgClient;
        try {
            // 去除补位字符
            byte[] bytes = PKCS7Padding.removePaddingBytes(originalArr);

            int plainTextLegth = Utils.bytes2int(Arrays.copyOfRange(bytes, RANDOM_LENGTH, 20));

            plaintext = new String(Arrays.copyOfRange(bytes, RANDOM_LENGTH + 4, RANDOM_LENGTH + 4 + plainTextLegth),
                    CHARSET);
            msgClient = new String(Arrays.copyOfRange(bytes, RANDOM_LENGTH + 4 + plainTextLegth, bytes.length),
                    CHARSET);
        } catch (Exception e) {
            throw new CallbackCryptoException(CallbackCryptoException.COMPUTE_DECRYPT_TEXT_LENGTH_ERROR);
        }

        // clientId不相同的情况
        if (!msgClient.equals(clientId)) {
            throw new CallbackCryptoException(CallbackCryptoException.COMPUTE_DECRYPT_TEXT_CLIENTID_ERROR);
        }
        return plaintext;
    }

    /**
     * 生成数字签名
     *
     * @param timestamp 时间戳
     * @param nonce     随机串
     * @param encrypt   加密文本
     * @return 数字签名
     * @throws CallbackCryptoException
     */
    public String getSignature(String timestamp, String nonce, String encrypt)
            throws CallbackCryptoException {
        try {
            String[] array = new String[] {this.clientId, timestamp, nonce, encrypt };
            Arrays.sort(array);

            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < 4; i++) {
                sb.append(array[i]);
            }
            String str = sb.toString();

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(str.getBytes());
            byte[] digest = md.digest();

            StringBuffer hexstr = new StringBuffer();
            String shaHex = "";
            for (int i = 0; i < digest.length; i++) {
                shaHex = Integer.toHexString(digest[i] & 0xFF);
                if (shaHex.length() < 2) {
                    hexstr.append(0);
                }
                hexstr.append(shaHex);
            }
            return hexstr.toString();
        } catch (Exception e) {
            throw new CallbackCryptoException(CallbackCryptoException.COMPUTE_SIGNATURE_ERROR);
        }
    }

    /**
     * 开放平台加解密异常类
     */
    public static class CallbackCryptoException extends Exception {
        public static final int SUCCESS = 0;
        public static final int ENCRYPTION_PLAINTEXT_ILLEGAL = 900001;
        public static final int AES_KEY_ILLEGAL = 900004;
        public static final int SIGNATURE_NOT_MATCH = 900005;
        public static final int COMPUTE_SIGNATURE_ERROR = 900006;
        public static final int COMPUTE_ENCRYPT_TEXT_ERROR = 900007;
        public static final int COMPUTE_DECRYPT_TEXT_ERROR = 900008;
        public static final int COMPUTE_DECRYPT_TEXT_LENGTH_ERROR = 900009;
        public static final int COMPUTE_DECRYPT_TEXT_CLIENTID_ERROR = 900010;
        private static Map<Integer, String> msgMap = new HashMap<Integer, String>();
        private int code = SUCCESS;

        static {
            msgMap.put(SUCCESS, "成功");
            msgMap.put(ENCRYPTION_PLAINTEXT_ILLEGAL, "加密明文文本非法");
            msgMap.put(AES_KEY_ILLEGAL, "不合法的aes key");
            msgMap.put(SIGNATURE_NOT_MATCH, "签名不匹配");
            msgMap.put(COMPUTE_SIGNATURE_ERROR, "签名计算失败");
            msgMap.put(COMPUTE_ENCRYPT_TEXT_ERROR, "计算加密文字错误");
            msgMap.put(COMPUTE_DECRYPT_TEXT_ERROR, "计算解密文字错误");
            msgMap.put(COMPUTE_DECRYPT_TEXT_LENGTH_ERROR, "计算解密文字长度不匹配");
            msgMap.put(COMPUTE_DECRYPT_TEXT_CLIENTID_ERROR, "计算解密文字clientId不匹配");
        }

        public Integer getCode() {
            return this.code;
        }

        public CallbackCryptoException(Integer exceptionCode) {
            super((String) msgMap.get(exceptionCode));
            this.code = exceptionCode;
        }
    }

    /**
     * PKCS7算法的加密填充
     */
    public static class PKCS7Padding {
        private static final Charset CHARSET = Charset.forName("utf-8");
        private static final int BLOCK_SIZE = 32;

        public PKCS7Padding() {
        }

        /**
         * 填充mode字节
         *
         * @param count
         */
        public static byte[] getPaddingBytes(int count) {
            int amountToPad = BLOCK_SIZE - count % BLOCK_SIZE;
            if (amountToPad == 0) {
                amountToPad = BLOCK_SIZE;
            }

            char padChr = chr(amountToPad);
            String tmp = new String();

            for (int index = 0; index < amountToPad; index++) {
                tmp = tmp + padChr;
            }

            return tmp.getBytes(CHARSET);
        }

        /**
         * 移除mode填充字节
         *
         * @param decrypted
         */
        public static byte[] removePaddingBytes(byte[] decrypted) {
            int pad = decrypted[decrypted.length - 1];
            if (pad < 1 || pad > BLOCK_SIZE) {
                pad = 0;
            }

            return Arrays.copyOfRange(decrypted, 0, decrypted.length - pad);
        }

        private static char chr(int a) {
            byte target = (byte) (a & 0xFF);
            return (char) target;
        }
    }

    /**
     * 加解密工具类
     */
    public static class Utils {
        public Utils() {
        }

        public static String getRandomStr(int count) {
            String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            StringBuffer sb = new StringBuffer();

            for (int i = 0; i < count; ++i) {
                int number = random.nextInt(chars.length());
                sb.append(chars.charAt(number));
            }

            return sb.toString();
        }

        public static byte[] int2Bytes(int number) {
            return new byte[] {
                    (byte) (number >> 24 & 0xFF),
                    (byte) (number >> 16 & 0xFF),
                    (byte) (number >> 8 & 0xFF),
                    (byte) (number & 0xFF)
            };
        }

        public static int bytes2int(byte[] byteArr) {
            int count = 0;

            for (int i = 0; i < 4; ++i) {
                count <<= 8;
                count |= byteArr[i] & 255;
            }

            return count;
        }
    }
}