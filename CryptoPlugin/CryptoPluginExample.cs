using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace CryptoPluginExample
{
    public class CryptoPluginExample
    {
        //                                  00000000011111111112222222222333
        //                                  12345678901234567890123456789012
        private const string _passPhrase = "                                "; // 32
        private const string _saltValue = @"                                "; // 32

        //                                  0000000001111111
        //                                  1234567890123456
        private const string _initVector = "                "; // 16

        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="plainText">The plaintext to encrypt</param>
        /// <returns>The ciphertext</returns>
        public static string Encrypt(string plainText, string passPhrase = "")
        {
            if(string.IsNullOrEmpty(passPhrase))
            {
                passPhrase = _passPhrase;
            }

            byte[] initVectorBytes = Encoding.ASCII.GetBytes(_initVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(_saltValue);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, 1000);
            byte[] keyBytes = password.GetBytes(16);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();
            byte[] cipherTextBytes = memoryStream.ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            string cipherText = Convert.ToBase64String(cipherTextBytes);
            return cipherText;
        }

        /// <summary>
        /// Decryption
        /// </summary>
        /// <param name="cipherText">The ciphertext to decrypt</param>
        /// <returns>The plaintext</returns>
        public static string Decrypt(string cipherText, string passPhrase = "")
        {
            if (string.IsNullOrEmpty(passPhrase))
            {
                passPhrase = _passPhrase;
            }

            byte[] initVectorBytes = Encoding.ASCII.GetBytes(_initVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(_saltValue);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, 1000);
            byte[] keyBytes = password.GetBytes(16);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
            string plainText = string.Empty;
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            {
                byte[] plainTextBytes = new byte[cipherTextBytes.Length];
                int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                memoryStream.Close();
                plainText = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
            }

            return plainText;
        }        
    }
}
