using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace WebApi
{
    public class CallbackCrypto
    {
        private readonly byte[] _aesKey;
        private readonly string _clientId;

        //随机字符串字节长度
        private static readonly int RANDOM_LENGTH = 16;

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="encodingAesKey">开放平台上，开发者设置的EncodingAESKey</param>
        /// <param name="clientId">开放平台上，应用的clientId</param>
        /// <exception cref="CallbackCryptoException"></exception>
        public CallbackCrypto(string encodingAesKey, string clientId)
        {
            if (encodingAesKey==null)
            {
                throw new Exception("加密密钥不能为空");
            }

            _clientId = clientId;
            _aesKey = Convert.FromBase64String(encodingAesKey);
        }

        /// <summary>
        /// 将和开放平台同步的消息体加密,返回加密Map
        /// </summary>
        /// <param name="plaintext">传递的消息体明文</param>
        /// <returns></returns>
        public Dictionary<string, string> GetEncryptedMap([NotNull] string plaintext)
        {
            return GetEncryptedMap(plaintext, DateTime.Now.Millisecond);
        }

        /// <summary>
        /// 将和开放平台同步的消息体加密,返回加密Map
        /// </summary>
        /// <param name="plaintext">传递的消息体明文</param>
        /// <param name="timestamp">时间戳</param>
        /// <returns></returns>
        /// <exception cref="CallbackCryptoException"></exception>
        public Dictionary<string, string> GetEncryptedMap([NotNull] string plaintext, long timestamp)
        {
            if (null == plaintext)
            {
                throw new Exception("加密明文字符串不能为空");
            }

            var nonce = Utils.GetRandomStr(RANDOM_LENGTH);
            string encrypt = Encrypt(nonce, plaintext);
            string signature = GetSignature(timestamp.ToString(), nonce, encrypt);

            return new Dictionary<string, string>()
            {
                ["signature"] = signature,
                ["encrypt"] = encrypt,
                ["timestamp"] = timestamp.ToString(),
                ["nonce"] = nonce
            };
        }

        /// <summary>
        /// 密文解密
        /// </summary>
        /// <param name="msgSignature">签名串</param>
        /// <param name="timestamp">时间戳</param>
        /// <param name="nonce">随机串</param>
        /// <param name="encryptMsg">密文</param>
        /// <returns>解密后的原文</returns>
        /// <exception cref="CallbackCryptoException"></exception>
        public string GetDecryptMsg(string msgSignature, string timestamp, string nonce, string encryptMsg)
        {
            //校验签名
            string signature = GetSignature(timestamp, nonce, encryptMsg);
            if (!signature.Equals(msgSignature))
            {
                throw new Exception("签名不匹配");
            }

            // 解密
            return Decrypt(encryptMsg);
        }

        /// <summary>
        /// 对明文加密
        /// </summary>
        /// <param name="nonce">随机串</param>
        /// <param name="plaintext">需要加密的明文</param>
        /// <returns>加密后base64编码的字符串</returns>
        /// <exception cref="CallbackCryptoException"></exception>
        private string Encrypt(string nonce, string plaintext)
        {

            byte[] randomBytes = Encoding.UTF8.GetBytes(nonce);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] lengthByte = Utils.Int2Bytes(plainTextBytes.Length);
            byte[] clientIdBytes = Encoding.UTF8.GetBytes(_clientId);

            var bytestmp = new List<byte>();
            bytestmp.AddRange(randomBytes);
            bytestmp.AddRange(lengthByte);
            bytestmp.AddRange(plainTextBytes);
            bytestmp.AddRange(clientIdBytes);

            byte[] padBytes = PKCS7Padding.GetPaddingBytes(bytestmp.Count);
            bytestmp.AddRange(padBytes);
            byte[] unencrypted = bytestmp.ToArray();

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Key = _aesKey;
                aesAlg.IV = _aesKey.ToList().Take(16).ToArray();

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                byte[] encrypted = encryptor.TransformFinalBlock(unencrypted, 0, unencrypted.Length);
                return Convert.ToBase64String(encrypted, 0, encrypted.Length);
            }
        }

        /// <summary>
        /// 对密文进行解密
        /// </summary>
        /// <param name="text">需要解密的密文</param>
        /// <returns>解密得到的明文</returns>
        /// <exception cref="CallbackCryptoException"></exception>
        private string Decrypt(string text)
        {
            byte[] originalArr;

            byte[] toEncryptArray = Convert.FromBase64String(text);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Key = _aesKey;
                aesAlg.IV = _aesKey.ToList().Take(16).ToArray();

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                originalArr = decryptor.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            }


            string plaintext;
            string msgClientId;

            // 去除补位字符
            byte[] bytes = PKCS7Padding.RemovePaddingBytes(originalArr);

            int plainTextLegth = Utils.Bytes2int(bytes.Skip(RANDOM_LENGTH).Take(4).ToArray());

            plaintext = Encoding.UTF8.GetString(bytes.Skip(RANDOM_LENGTH + 4).Take(plainTextLegth).ToArray());
            msgClientId = Encoding.UTF8.GetString(bytes.Skip(RANDOM_LENGTH + 4 + plainTextLegth).ToArray());


            return !msgClientId.Equals(_clientId)
                ? throw new Exception("计算解密文字clientId不匹配")
                : plaintext;
        }

        /// <summary>
        /// 生成数字签名
        /// </summary>
        /// <param name="timestamp">时间戳</param>
        /// <param name="nonce">随机串</param>
        /// <param name="encrypt">加密文本</param>
        /// <returns></returns>
        /// <exception cref="CallbackCryptoException"></exception>
        public string GetSignature(string timestamp, string nonce, string encrypt)
        {
            string[] array = new string[] { _clientId, timestamp, nonce, encrypt };
            Array.Sort(array, StringComparer.Ordinal);

            byte[] digest = SHA1.HashData(Encoding.ASCII.GetBytes(string.Join(string.Empty, array)));

            StringBuilder hexstr = new StringBuilder();
            for (int i = 0; i < digest.Length; i++)
            {
                hexstr.Append(((int)digest[i]).ToString("x2"));
            }

            return hexstr.ToString();
        }
    }

    /// <summary>
    /// 加解密工具类
    /// </summary>
    public class Utils
    {
        public static string GetRandomStr(int count)
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < count; i++)
            {
                int number = random.Next(chars.Length);
                sb.Append(chars[number]);
            }

            return sb.ToString();
        }

        /// <summary>
        /// int转byte数组,高位在前
        /// </summary>
        public static byte[] Int2Bytes(int number)
        {
            return new byte[]
            {
                (byte) (number >> 24 & 0xFF),
                (byte) (number >> 16 & 0xFF),
                (byte) (number >> 8 & 0xFF),
                (byte) (number & 0xFF)
            };
        }

        /// <summary>
        /// 高位在前bytes数组转int
        /// </summary>
        public static int Bytes2int(byte[] byteArr)
        {
            int count = 0;
            for (int i = 0; i < 4; ++i)
            {
                count <<= 8;
                count |= byteArr[i] & 255;
            }

            return count;
        }
    }

    /// <summary>
    /// PKCS7算法的加密填充
    /// </summary>
    public class PKCS7Padding
    {
        private static readonly int BLOCK_SIZE = 32;

        /// <summary>
        /// 填充mode字节
        /// </summary>
        /// <param name="count"></param>
        public static byte[] GetPaddingBytes(int count)
        {
            int amountToPad = BLOCK_SIZE - count % BLOCK_SIZE;
            if (amountToPad == 0)
            {
                amountToPad = BLOCK_SIZE;
            }

            char padChr = Chr(amountToPad);
            string tmp = string.Empty;
            for (int index = 0; index < amountToPad; index++)
            {
                tmp += padChr;
            }

            return Encoding.UTF8.GetBytes(tmp);
        }

        /// <summary>
        /// 移除mode填充字节
        /// </summary>
        /// <param name="decrypted"></param>
        public static byte[] RemovePaddingBytes(byte[] decrypted)
        {
            int pad = decrypted[^1];
            if (pad < 1 || pad > BLOCK_SIZE)
            {
                pad = 0;
            }

            var output = new byte[decrypted.Length - pad];
            Array.Copy(decrypted, output, decrypted.Length - pad);

            return output;
        }

        private static char Chr(int a)
        {
            byte target = (byte)(a & 0xFF);
            return (char)target;
        }
    }
}
