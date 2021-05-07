using System;
using System.Threading;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using System.Numerics;
using System.IO;
using System.Collections.Generic;
using System.Net;
using TLSharp.Core;
//using TLSharp.Core.MTProto.Crypto;

namespace ChatClient
{
    public class Chat
    {
        private byte[] key;
        private NetworkStream stream;
        private TcpClient client;
        string usernameB;
        byte[] key_fingerprint;

        public Chat(NetworkStream stream, TcpClient client, byte[] key, string usernameB, byte[] key_fingerprint)
        {
            this.key = key;
            this.stream = stream;
            this.client = client;
            this.usernameB = usernameB;
            this.key_fingerprint = key_fingerprint;
        }

        public void SendMessage()
        {
            Console.WriteLine("Введите сообщение: ");

            BinaryWriter writer = new BinaryWriter(stream);

            while (true)
            {
                string message = Console.ReadLine();
                byte[] plaintext = Encoding.Default.GetBytes(message);

                SHA256Managed hash = new SHA256Managed();
                //int size = 16;
                //byte[] random_padding;
                //using (var generator = RandomNumberGenerator.Create())
                //{
                //    random_padding = new byte[size];
                //    generator.GetBytes(random_padding);
                //}

                //byte[] subKey = new byte[32 + plaintext.Length + random_padding.Length];

                byte[] subKey = new byte[plaintext.Length];
                //Buffer.BlockCopy(key, 88 + 8, subKey, 0, 32);
                //Buffer.BlockCopy(plaintext, 0, subKey, 32, plaintext.Length);
                //Buffer.BlockCopy(random_padding, 0, subKey, 32 + plaintext.Length, random_padding.Length);

                Buffer.BlockCopy(plaintext, 0, subKey, 0, plaintext.Length);

                //using (MemoryStream plaintextBuffer = new MemoryStream(subKey.Length + 1024))
                //{
                //    plaintextBuffer.Write(subKey, 0, subKey.Length);
                //    while (plaintextBuffer.Position % 16 != 0)
                //    {
                //        plaintextBuffer.WriteByte(0); // TODO: random padding
                //    }
                //    subKey = plaintextBuffer.ToArray();
                //}

                //string text = subKey + "простойтекст". + "рандомные символы";
                byte[] msg_key_large = hash.ComputeHash(subKey);
                byte[] msg_key = new byte[16];
                Buffer.BlockCopy(msg_key_large, 8, msg_key, 0, 16);
                List<byte[]> KeyAndIV = KDF(key, msg_key);
                byte[] EncryptedData = EncryptIGE(subKey, KeyAndIV[0], KeyAndIV[1]);
                //byte[] data = Encrypt(message, key, iv);
                byte[] send_message = new byte[key_fingerprint.Length + msg_key.Length + EncryptedData.Length];
                Buffer.BlockCopy(key_fingerprint, 0, send_message, 0, key_fingerprint.Length);
                Buffer.BlockCopy(msg_key, 0, send_message, key_fingerprint.Length, msg_key.Length);
                Buffer.BlockCopy(EncryptedData, 0, send_message, key_fingerprint.Length + msg_key.Length, EncryptedData.Length);
                string message_bytes = System.Text.Encoding.Default.GetString(send_message);
                writer.Write(message_bytes);
            }
        }
        static List<byte[]> KDF(byte[] key, byte[] msg_key)
        {
            SHA256Managed hash = new SHA256Managed();

            //byte[] key = keyInt.ToByteArray();
            //byte[] plainttextBytes = Encoding.Default.GetBytes(plaintext);
            //byte[] subKey = new byte[32 + plainttextBytes.Length];
            //Buffer.BlockCopy(key, 88 + 8, subKey, 0, 32);
            //Buffer.BlockCopy(plainttextBytes, 0, subKey, 32, plainttextBytes.Length);
            //using (MemoryStream plaintextBuffer = new MemoryStream(subKey.Length + 40))
            //{
            //    plaintextBuffer.Write(subKey, 0, subKey.Length);
            //    while (plaintextBuffer.Position % 16 != 0)
            //    {
            //        plaintextBuffer.WriteByte(0); // TODO: random padding
            //    }
            //    subKey = plaintextBuffer.ToArray();
            //}
            ////string text = subKey + "простойтекст". + "рандомные символы";
            //byte[] msg_key_large = hash.ComputeHash(subKey);
            //byte[] msg_key = new byte[16];
            //Buffer.BlockCopy(msg_key_large, 8, msg_key, 0, 16);
            byte[] sha256_a = new byte[16 + 36];
            Buffer.BlockCopy(key, 8, sha256_a, 0, 36);
            Buffer.BlockCopy(msg_key, 0, sha256_a, 0, 16);
            sha256_a = hash.ComputeHash(sha256_a);
            //string sha256_a = getHashSha256(msg_key + key.ToString().Substring(8, 36));
            byte[] sha256_b = new byte[16 + 36];
            Buffer.BlockCopy(key, 48, sha256_b, 0, 36);
            Buffer.BlockCopy(msg_key, 0, sha256_b, 36, 16);
            sha256_b = hash.ComputeHash(sha256_b);
            //string sha256_b = getHashSha256(key.ToString().Substring(40 + 8, 36) + msg_key);
            byte[] aes_key = new byte[8 + 16 + 8];
            Buffer.BlockCopy(sha256_a, 0, aes_key, 0, 8);
            Buffer.BlockCopy(sha256_b, 8, aes_key, 8, 16);
            Buffer.BlockCopy(sha256_a, 24, aes_key, 24, 8);
            //aes_key = hash.ComputeHash(aes_key);
            //string aes_key = (sha256_a.Substring(0, 8) + sha256_b.Substring(8, 16) + sha256_a.Substring(24, 8));
            //byte[] aes_iv = new byte[8 + 16 + 8];
            byte[] aes_iv = new byte[32];
            Buffer.BlockCopy(sha256_b, 0, aes_iv, 0, 8);
            Buffer.BlockCopy(sha256_a, 8, aes_iv, 8, 16);
            Buffer.BlockCopy(sha256_b, 24, aes_iv, 24, 8);
            //aes_iv = hash.ComputeHash(aes_iv);
            //string aes_iv = sha256_b.Substring(0, 8) + sha256_a.Substring(8, 16) + sha256_b.Substring(24, 8);
            return new List<byte[]> { aes_key, aes_iv };
        }
        public void ReceiveMessage()
        {
            while (true)
            {
                try
                {
                    string message;
                    byte[] messageBytes;
                    BinaryReader reader = new BinaryReader(stream);
                    do
                    {
                        string data = reader.ReadString();
                        byte[] message_bytes = Encoding.Default.GetBytes(data);
                        byte[] key_fingerprint_from_msg = new byte[key_fingerprint.Length];
                        byte[] msg_key_from_msg = new byte[16];
                        byte[] EncryptedData = new byte[message_bytes.Length-key_fingerprint_from_msg.Length-msg_key_from_msg.Length];
                        Buffer.BlockCopy(message_bytes, 0, key_fingerprint_from_msg, 0, key_fingerprint_from_msg.Length);
                        Buffer.BlockCopy(message_bytes, key_fingerprint_from_msg.Length, msg_key_from_msg, 0, msg_key_from_msg.Length);
                        Buffer.BlockCopy(message_bytes, key_fingerprint_from_msg.Length+16, EncryptedData, 0, EncryptedData.Length);
                        BigInteger key1 = new BigInteger(key_fingerprint);
                        Console.WriteLine("key_fingerprint: {0}", key1.ToString());
                        BigInteger key2 = new BigInteger(key_fingerprint_from_msg);
                        Console.WriteLine("key_fingerprint_from_msg: {0}", key2.ToString());
                        if (key1 != key2)
                        {
                            Console.WriteLine("key_fingerprint не совпадает с Вашим.");
                        }
                       
                        List<byte[]> KeyAndIV = KDF(key, msg_key_from_msg);
                        messageBytes = DecryptIGE(EncryptedData, KeyAndIV[0], KeyAndIV[1]);
                        messageBytes = Encoding.Default.GetBytes(System.Text.Encoding.Default.GetString(messageBytes));
                        SHA256Managed hash = new SHA256Managed();
                        byte[] msg_key_large = hash.ComputeHash(messageBytes);
                        byte[] msg_key = new byte[16];
                        Buffer.BlockCopy(msg_key_large, 8, msg_key, 0, 16);

                        BigInteger msg_key1 = new BigInteger(msg_key);
                        Console.WriteLine("msg_key: {0}", msg_key1.ToString());
                        BigInteger msg_key2 = new BigInteger(msg_key_from_msg);
                        Console.WriteLine("msg_key_from_msg: {0}", msg_key2.ToString());

                        if (msg_key1 != msg_key2)
                        {
                            Console.WriteLine("msg_key_from_msg не совпадает с SHA256(plaintext).");
                        }
                        message = System.Text.Encoding.Default.GetString(messageBytes);
                        //message = Decrypt(dataBytes, key, iv);
                    }
                    while (stream.DataAvailable);

                    Console.WriteLine("{0}: {1}", usernameB, message);//вывод сообщения
                }
                catch (Exception exp)
                {
                    Console.WriteLine(exp.Message);
                    Console.WriteLine("Подключение прервано!"); //соединение было прервано
                    Disconnect();
                }
            }
        }
        static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            // Create a new AesManaged.    
            using (AesManaged aes = new AesManaged())
            {
                // Create encryptor    
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
                // Create MemoryStream    
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption    
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                    // to encrypt    
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream    
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data    
            return encrypted;
        }
        public string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            // Create AesManaged    
            using (AesManaged aes = new AesManaged())
            {
                // Create a decryptor    
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.    
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream    
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream    
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }
        void Disconnect()
        {
            if (stream != null)
                stream.Close();//отключение потока
            if (client != null)
                client.Close();//отключение клиента
            Environment.Exit(0); //завершение процесса
        }

        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            // Return the encrypted bytes from the memory stream. 
            return encrypted;
        }
        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }


        ////////////////////////////////////////////////////////////////////////////////////////////
       

        public static byte[] DecryptIGE(byte[] ciphertext, byte[] key, byte[] iv)
        {
            var iv1 = new byte[iv.Length / 2];
            var iv2 = new byte[iv.Length / 2];

            Array.Copy(iv, 0, iv1, 0, iv1.Length);
            Array.Copy(iv, iv1.Length, iv2, 0, iv2.Length);

            AesEngine aes = new AesEngine();
            aes.Init(false, key);

            byte[] plaintext = new byte[ciphertext.Length];
            int blocksCount = ciphertext.Length / 16;

            byte[] ciphertextBlock = new byte[16];
            byte[] plaintextBlock = new byte[16];
            for (int blockIndex = 0; blockIndex < blocksCount; blockIndex++)
            {
                for (int i = 0; i < 16; i++)
                {
                    ciphertextBlock[i] = (byte)(ciphertext[blockIndex * 16 + i] ^ iv2[i]);
                }

                aes.ProcessBlock(ciphertextBlock, 0, plaintextBlock, 0);

                for (int i = 0; i < 16; i++)
                {
                    plaintextBlock[i] ^= iv1[i];
                }

                Array.Copy(ciphertext, blockIndex * 16, iv1, 0, 16);
                Array.Copy(plaintextBlock, 0, iv2, 0, 16);

                Array.Copy(plaintextBlock, 0, plaintext, blockIndex * 16, 16);
            }

            return plaintext;
        }

        public static byte[] EncryptIGE(byte[] originPlaintext, byte[] key, byte[] iv)
        {

            byte[] plaintext;
            using (MemoryStream plaintextBuffer = new MemoryStream(originPlaintext.Length + 40))
            {
                //using(SHA1 hash = new SHA1Managed()) {
                //byte[] hashsum = hash.ComputeHash(originPlaintext);
                //plaintextBuffer.Write(hashsum, 0, hashsum.Length);
                plaintextBuffer.Write(originPlaintext, 0, originPlaintext.Length);
                while (plaintextBuffer.Position % 16 != 0)
                {
                    plaintextBuffer.WriteByte(0); // TODO: random padding
                }
                plaintext = plaintextBuffer.ToArray();
            }

            var iv1 = new byte[iv.Length / 2];
            var iv2 = new byte[iv.Length / 2];

            Array.Copy(iv, 0, iv1, 0, iv1.Length);
            Array.Copy(iv, iv1.Length, iv2, 0, iv2.Length);

            AesEngine aes = new AesEngine();
            aes.Init(true, key);

            int blocksCount = plaintext.Length / 16;
            byte[] ciphertext = new byte[plaintext.Length];

            byte[] ciphertextBlock = new byte[16];
            byte[] plaintextBlock = new byte[16];
            for (int blockIndex = 0; blockIndex < blocksCount; blockIndex++)
            {
                Array.Copy(plaintext, 16 * blockIndex, plaintextBlock, 0, 16);

                //logger.info("plaintext block: {0} xor {1}", BitConverter.ToString(plaintextBlock).Replace("-", ""), BitConverter.ToString(iv1).Replace("-", ""));

                for (int i = 0; i < 16; i++)
                {
                    plaintextBlock[i] ^= iv1[i];
                }

                //logger.info("xored plaintext: {0}", BitConverter.ToString(plaintextBlock).Replace("-", ""));

                aes.ProcessBlock(plaintextBlock, 0, ciphertextBlock, 0);

                //logger.info("encrypted plaintext: {0} xor {1}", BitConverter.ToString(ciphertextBlock).Replace("-", ""), BitConverter.ToString(iv2).Replace("-", ""));

                for (int i = 0; i < 16; i++)
                {
                    ciphertextBlock[i] ^= iv2[i];
                }

                //logger.info("xored ciphertext: {0}", BitConverter.ToString(ciphertextBlock).Replace("-", ""));

                Array.Copy(ciphertextBlock, 0, iv1, 0, 16);
                Array.Copy(plaintext, 16 * blockIndex, iv2, 0, 16);

                Array.Copy(ciphertextBlock, 0, ciphertext, blockIndex * 16, 16);
            }

            return ciphertext;
        }

        public static byte[] XOR(byte[] buffer1, byte[] buffer2)
        {
            var result = new byte[buffer1.Length];
            for (int i = 0; i < buffer1.Length; i++)
                result[i] = (byte)(buffer1[i] ^ buffer2[i]);
            return result;
        }
    }

    public class AesEngine
    {
        // The S box
        private const uint m1 = 0x80808080;
        private const uint m2 = 0x7f7f7f7f;
        private const uint m3 = 0x0000001b;
        private const int BLOCK_SIZE = 16;

        private static readonly byte[] S = {
            99, 124, 119, 123, 242, 107, 111, 197,
            48, 1, 103, 43, 254, 215, 171, 118,
            202, 130, 201, 125, 250, 89, 71, 240,
            173, 212, 162, 175, 156, 164, 114, 192,
            183, 253, 147, 38, 54, 63, 247, 204,
            52, 165, 229, 241, 113, 216, 49, 21,
            4, 199, 35, 195, 24, 150, 5, 154,
            7, 18, 128, 226, 235, 39, 178, 117,
            9, 131, 44, 26, 27, 110, 90, 160,
            82, 59, 214, 179, 41, 227, 47, 132,
            83, 209, 0, 237, 32, 252, 177, 91,
            106, 203, 190, 57, 74, 76, 88, 207,
            208, 239, 170, 251, 67, 77, 51, 133,
            69, 249, 2, 127, 80, 60, 159, 168,
            81, 163, 64, 143, 146, 157, 56, 245,
            188, 182, 218, 33, 16, 255, 243, 210,
            205, 12, 19, 236, 95, 151, 68, 23,
            196, 167, 126, 61, 100, 93, 25, 115,
            96, 129, 79, 220, 34, 42, 144, 136,
            70, 238, 184, 20, 222, 94, 11, 219,
            224, 50, 58, 10, 73, 6, 36, 92,
            194, 211, 172, 98, 145, 149, 228, 121,
            231, 200, 55, 109, 141, 213, 78, 169,
            108, 86, 244, 234, 101, 122, 174, 8,
            186, 120, 37, 46, 28, 166, 180, 198,
            232, 221, 116, 31, 75, 189, 139, 138,
            112, 62, 181, 102, 72, 3, 246, 14,
            97, 53, 87, 185, 134, 193, 29, 158,
            225, 248, 152, 17, 105, 217, 142, 148,
            155, 30, 135, 233, 206, 85, 40, 223,
            140, 161, 137, 13, 191, 230, 66, 104,
            65, 153, 45, 15, 176, 84, 187, 22
        };

        // The inverse S-box
        private static readonly byte[] Si = {
            82, 9, 106, 213, 48, 54, 165, 56,
            191, 64, 163, 158, 129, 243, 215, 251,
            124, 227, 57, 130, 155, 47, 255, 135,
            52, 142, 67, 68, 196, 222, 233, 203,
            84, 123, 148, 50, 166, 194, 35, 61,
            238, 76, 149, 11, 66, 250, 195, 78,
            8, 46, 161, 102, 40, 217, 36, 178,
            118, 91, 162, 73, 109, 139, 209, 37,
            114, 248, 246, 100, 134, 104, 152, 22,
            212, 164, 92, 204, 93, 101, 182, 146,
            108, 112, 72, 80, 253, 237, 185, 218,
            94, 21, 70, 87, 167, 141, 157, 132,
            144, 216, 171, 0, 140, 188, 211, 10,
            247, 228, 88, 5, 184, 179, 69, 6,
            208, 44, 30, 143, 202, 63, 15, 2,
            193, 175, 189, 3, 1, 19, 138, 107,
            58, 145, 17, 65, 79, 103, 220, 234,
            151, 242, 207, 206, 240, 180, 230, 115,
            150, 172, 116, 34, 231, 173, 53, 133,
            226, 249, 55, 232, 28, 117, 223, 110,
            71, 241, 26, 113, 29, 41, 197, 137,
            111, 183, 98, 14, 170, 24, 190, 27,
            252, 86, 62, 75, 198, 210, 121, 32,
            154, 219, 192, 254, 120, 205, 90, 244,
            31, 221, 168, 51, 136, 7, 199, 49,
            177, 18, 16, 89, 39, 128, 236, 95,
            96, 81, 127, 169, 25, 181, 74, 13,
            45, 229, 122, 159, 147, 201, 156, 239,
            160, 224, 59, 77, 174, 42, 245, 176,
            200, 235, 187, 60, 131, 83, 153, 97,
            23, 43, 4, 126, 186, 119, 214, 38,
            225, 105, 20, 99, 85, 33, 12, 125
        };

        // vector used in calculating key schedule (powers of x in GF(256))
        private static readonly byte[] rcon = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
        };

        // precomputation tables of calculations for rounds
        private static readonly uint[] T0 = {
            0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff,
            0xbd6b6bd6, 0xb16f6fde, 0x54c5c591, 0x50303060, 0x03010102,
            0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d,
            0x9a7676ec, 0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa,
            0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb, 0xecadad41,
            0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453,
            0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d,
            0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
            0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2,
            0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795,
            0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a,
            0xb59a9a2f, 0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
            0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912,
            0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc,
            0xee5a5ab4, 0xfba0a05b, 0xf65252a4, 0x4d3b3b76, 0x61d6d6b7,
            0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
            0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040,
            0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d,
            0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0,
            0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed,
            0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511, 0xcf45458a,
            0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78,
            0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d, 0xc0404080,
            0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
            0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020,
            0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18,
            0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488,
            0x3917172e, 0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a,
            0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6, 0xa06060c0,
            0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54,
            0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b,
            0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
            0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992,
            0x0a06060c, 0x6c242448, 0xe45c5cb8, 0x5dc2c29f, 0x6ed3d3bd,
            0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3,
            0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
            0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8,
            0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4,
            0xe9aeae47, 0x18080810, 0xd5baba6f, 0x887878f0, 0x6f25254a,
            0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
            0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96,
            0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c,
            0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7,
            0x120e0e1c, 0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969,
            0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27, 0x38e1e1d9,
            0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9,
            0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c, 0x92878715,
            0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
            0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65,
            0x31e6e6d7, 0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929,
            0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d,
            0x3a16162c
        };

        private static readonly uint[] Tinv0 = {
            0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a, 0xcb6bab3b,
            0xf1459d1f, 0xab58faac, 0x9303e34b, 0x55fa3020, 0xf66d76ad,
            0x9176cc88, 0x254c02f5, 0xfcd7e54f, 0xd7cb2ac5, 0x80443526,
            0x8fa362b5, 0x495ab1de, 0x671bba25, 0x980eea45, 0xe1c0fe5d,
            0x02752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b, 0xe75f8f03,
            0x959c9215, 0xeb7a6dbf, 0xda595295, 0x2d83bed4, 0xd3217458,
            0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899,
            0xdd71b927, 0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d,
            0x184adf63, 0x82311ae5, 0x60335197, 0x457f5362, 0xe07764b1,
            0x84ae6bbb, 0x1ca081fe, 0x942b08f9, 0x58684870, 0x19fd458f,
            0x876cde94, 0xb7f87b52, 0x23d373ab, 0xe2024b72, 0x578f1fe3,
            0x2aab5566, 0x0728ebb2, 0x03c2b52f, 0x9a7bc586, 0xa50837d3,
            0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed, 0x2b1ccf8a,
            0x92b479a7, 0xf0f207f3, 0xa1e2694e, 0xcdf4da65, 0xd5be0506,
            0x1f6234d1, 0x8afea6c4, 0x9d532e34, 0xa055f3a2, 0x32e18a05,
            0x75ebf6a4, 0x39ec830b, 0xaaef6040, 0x069f715e, 0x51106ebd,
            0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d, 0xb58d5491,
            0x055dc471, 0x6fd40604, 0xff155060, 0x24fb9819, 0x97e9bdd6,
            0xcc434089, 0x779ed967, 0xbd42e8b0, 0x888b8907, 0x385b19e7,
            0xdbeec879, 0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x00000000,
            0x83868009, 0x48ed2b32, 0xac70111e, 0x4e725a6c, 0xfbff0efd,
            0x5638850f, 0x1ed5ae3d, 0x27392d36, 0x64d90f0a, 0x21a65c68,
            0xd1545b9b, 0x3a2e3624, 0xb1670a0c, 0x0fe75793, 0xd296eeb4,
            0x9e919b1b, 0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c,
            0x0aba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12, 0x0b0d090e,
            0xadc78bf2, 0xb9a8b62d, 0xc8a91e14, 0x8519f157, 0x4c0775af,
            0xbbdd99ee, 0xfd607fa3, 0x9f2601f7, 0xbcf5725c, 0xc53b6644,
            0x347efb5b, 0x7629438b, 0xdcc623cb, 0x68fcedb6, 0x63f1e4b8,
            0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684, 0x7d244a85,
            0xf83dbbd2, 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, 0xf330b2dc,
            0xec52860d, 0xd0e3c177, 0x6c16b32b, 0x99b970a9, 0xfa489411,
            0x2264e947, 0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322,
            0xc74e4987, 0xc1d138d9, 0xfea2ca8c, 0x360bd498, 0xcf81f5a6,
            0x28de7aa5, 0x268eb7da, 0xa4bfad3f, 0xe49d3a2c, 0x0d927850,
            0x9bcc5f6a, 0x62467e54, 0xc2138df6, 0xe8b8d890, 0x5ef7392e,
            0xf5afc382, 0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf,
            0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb, 0x097826cd,
            0xf418596e, 0x01b79aec, 0xa89a4f83, 0x656e95e6, 0x7ee6ffaa,
            0x08cfbc21, 0xe6e815ef, 0xd99be7ba, 0xce366f4a, 0xd4099fea,
            0xd67cb029, 0xafb2a431, 0x31233f2a, 0x3094a5c6, 0xc066a235,
            0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733, 0x4a9804f1,
            0xf7daec41, 0x0e50cd7f, 0x2ff69117, 0x8dd64d76, 0x4db0ef43,
            0x544daacc, 0xdf0496e4, 0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1,
            0x7f516546, 0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb,
            0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d, 0x8c61d79a,
            0x7a0ca137, 0x8e14f859, 0x893c13eb, 0xee27a9ce, 0x35c961b7,
            0xede51ce1, 0x3cb1477a, 0x59dfd29c, 0x3f73f255, 0x79ce1418,
            0xbf37c773, 0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478,
            0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16,
            0x0c25e2bc, 0x8b493c28, 0x41950dff, 0x7101a839, 0xdeb30c08,
            0x9ce4b4d8, 0x90c15664, 0x6184cb7b, 0x70b632d5, 0x745c6c48,
            0x4257b8d0
        };

        private uint C0, C1, C2, C3;
        private int ROUNDS;
        private uint[,] WorkingKey;
        private bool forEncryption;

        public string AlgorithmName
        {
            get { return "AES"; }
        }

        public bool IsPartialBlockOkay
        {
            get { return false; }
        }

        private uint Shift(
            uint r,
            int shift)
        {
            return (r >> shift) | (r << (32 - shift));
        }

        private uint FFmulX(
            uint x)
        {
            return ((x & m2) << 1) ^ (((x & m1) >> 7) * m3);
        }

        /*
        The following defines provide alternative definitions of FFmulX that might
        give improved performance if a fast 32-bit multiply is not available.
        private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); }
        private static final int  m4 = 0x1b1b1b1b;
        private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); }
        */

        private uint Inv_Mcol(
            uint x)
        {
            uint f2 = FFmulX(x);
            uint f4 = FFmulX(f2);
            uint f8 = FFmulX(f4);
            uint f9 = x ^ f8;

            return f2 ^ f4 ^ f8 ^ Shift(f2 ^ f9, 8) ^ Shift(f4 ^ f9, 16) ^ Shift(f9, 24);
        }

        private uint SubWord(
            uint x)
        {
            return S[x & 255]
                   | (((uint)S[(x >> 8) & 255]) << 8)
                   | (((uint)S[(x >> 16) & 255]) << 16)
                   | (((uint)S[(x >> 24) & 255]) << 24);
        }

        /**
        * Calculate the necessary round keys
        * The number of calculations depends on key size and block size
        * AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
        * This code is written assuming those are the only possible values
        */

        private uint[,] GenerateWorkingKey(
            byte[] key,
            bool forEncryption)
        {
            int KC = key.Length / 4; // key length in words
            int t;

            if ((KC != 4) && (KC != 6) && (KC != 8))
                throw new ArgumentException("Key length not 128/192/256 bits.");

            ROUNDS = KC + 6; // This is not always true for the generalized Rijndael that allows larger block sizes
            var W = new uint[ROUNDS + 1, 4]; // 4 words in a block

            //
            // copy the key into the round key array
            //

            t = 0;
            for (int i = 0; i < key.Length; t++)
            {
                W[t >> 2, t & 3] = Pack.LE_To_UInt32(key, i);
                i += 4;
            }

            //
            // while not enough round key material calculated
            // calculate new values
            //
            int k = (ROUNDS + 1) << 2;
            for (int i = KC; (i < k); i++)
            {
                uint temp = W[(i - 1) >> 2, (i - 1) & 3];
                if ((i % KC) == 0)
                {
                    temp = SubWord(Shift(temp, 8)) ^ rcon[(i / KC) - 1];
                }
                else if ((KC > 6) && ((i % KC) == 4))
                {
                    temp = SubWord(temp);
                }

                W[i >> 2, i & 3] = W[(i - KC) >> 2, (i - KC) & 3] ^ temp;
            }

            if (!forEncryption)
            {
                for (int j = 1; j < ROUNDS; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        W[j, i] = Inv_Mcol(W[j, i]);
                    }
                }
            }

            return W;
        }

        public void Init(bool forEncryption, byte[] key)
        {
            WorkingKey = GenerateWorkingKey(key, forEncryption);
            this.forEncryption = forEncryption;
        }

        public int GetBlockSize()
        {
            return BLOCK_SIZE;
        }

        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            if (WorkingKey == null)
            {
                throw new InvalidOperationException("AES engine not initialised");
            }

            if ((inOff + (32 / 2)) > input.Length)
            {
                throw new InvalidOperationException("input buffer too short");
            }

            if ((outOff + (32 / 2)) > output.Length)
            {
                throw new InvalidOperationException("output buffer too short");
            }

            UnPackBlock(input, inOff);

            if (forEncryption)
            {
                EncryptBlock(WorkingKey);
            }
            else
            {
                DecryptBlock(WorkingKey);
            }

            PackBlock(output, outOff);

            return BLOCK_SIZE;
        }

        public void Reset()
        {
        }

        private void UnPackBlock(
            byte[] bytes,
            int off)
        {
            C0 = Pack.LE_To_UInt32(bytes, off);
            C1 = Pack.LE_To_UInt32(bytes, off + 4);
            C2 = Pack.LE_To_UInt32(bytes, off + 8);
            C3 = Pack.LE_To_UInt32(bytes, off + 12);
        }

        private void PackBlock(
            byte[] bytes,
            int off)
        {
            Pack.UInt32_To_LE(C0, bytes, off);
            Pack.UInt32_To_LE(C1, bytes, off + 4);
            Pack.UInt32_To_LE(C2, bytes, off + 8);
            Pack.UInt32_To_LE(C3, bytes, off + 12);
        }

        private void EncryptBlock(
            uint[,] KW)
        {
            uint r, r0, r1, r2, r3;

            C0 ^= KW[0, 0];
            C1 ^= KW[0, 1];
            C2 ^= KW[0, 2];
            C3 ^= KW[0, 3];

            for (r = 1; r < ROUNDS - 1;)
            {
                r0 = T0[C0 & 255] ^ Shift(T0[(C1 >> 8) & 255], 24) ^ Shift(T0[(C2 >> 16) & 255], 16) ^
                     Shift(T0[(C3 >> 24) & 255], 8) ^ KW[r, 0];
                r1 = T0[C1 & 255] ^ Shift(T0[(C2 >> 8) & 255], 24) ^ Shift(T0[(C3 >> 16) & 255], 16) ^
                     Shift(T0[(C0 >> 24) & 255], 8) ^ KW[r, 1];
                r2 = T0[C2 & 255] ^ Shift(T0[(C3 >> 8) & 255], 24) ^ Shift(T0[(C0 >> 16) & 255], 16) ^
                     Shift(T0[(C1 >> 24) & 255], 8) ^ KW[r, 2];
                r3 = T0[C3 & 255] ^ Shift(T0[(C0 >> 8) & 255], 24) ^ Shift(T0[(C1 >> 16) & 255], 16) ^
                     Shift(T0[(C2 >> 24) & 255], 8) ^ KW[r++, 3];
                C0 = T0[r0 & 255] ^ Shift(T0[(r1 >> 8) & 255], 24) ^ Shift(T0[(r2 >> 16) & 255], 16) ^
                     Shift(T0[(r3 >> 24) & 255], 8) ^ KW[r, 0];
                C1 = T0[r1 & 255] ^ Shift(T0[(r2 >> 8) & 255], 24) ^ Shift(T0[(r3 >> 16) & 255], 16) ^
                     Shift(T0[(r0 >> 24) & 255], 8) ^ KW[r, 1];
                C2 = T0[r2 & 255] ^ Shift(T0[(r3 >> 8) & 255], 24) ^ Shift(T0[(r0 >> 16) & 255], 16) ^
                     Shift(T0[(r1 >> 24) & 255], 8) ^ KW[r, 2];
                C3 = T0[r3 & 255] ^ Shift(T0[(r0 >> 8) & 255], 24) ^ Shift(T0[(r1 >> 16) & 255], 16) ^
                     Shift(T0[(r2 >> 24) & 255], 8) ^ KW[r++, 3];
            }

            r0 = T0[C0 & 255] ^ Shift(T0[(C1 >> 8) & 255], 24) ^ Shift(T0[(C2 >> 16) & 255], 16) ^
                 Shift(T0[(C3 >> 24) & 255], 8) ^ KW[r, 0];
            r1 = T0[C1 & 255] ^ Shift(T0[(C2 >> 8) & 255], 24) ^ Shift(T0[(C3 >> 16) & 255], 16) ^
                 Shift(T0[(C0 >> 24) & 255], 8) ^ KW[r, 1];
            r2 = T0[C2 & 255] ^ Shift(T0[(C3 >> 8) & 255], 24) ^ Shift(T0[(C0 >> 16) & 255], 16) ^
                 Shift(T0[(C1 >> 24) & 255], 8) ^ KW[r, 2];
            r3 = T0[C3 & 255] ^ Shift(T0[(C0 >> 8) & 255], 24) ^ Shift(T0[(C1 >> 16) & 255], 16) ^
                 Shift(T0[(C2 >> 24) & 255], 8) ^ KW[r++, 3];

            // the final round's table is a simple function of S so we don't use a whole other four tables for it

            C0 = S[r0 & 255] ^ (((uint)S[(r1 >> 8) & 255]) << 8) ^ (((uint)S[(r2 >> 16) & 255]) << 16) ^
                 (((uint)S[(r3 >> 24) & 255]) << 24) ^ KW[r, 0];
            C1 = S[r1 & 255] ^ (((uint)S[(r2 >> 8) & 255]) << 8) ^ (((uint)S[(r3 >> 16) & 255]) << 16) ^
                 (((uint)S[(r0 >> 24) & 255]) << 24) ^ KW[r, 1];
            C2 = S[r2 & 255] ^ (((uint)S[(r3 >> 8) & 255]) << 8) ^ (((uint)S[(r0 >> 16) & 255]) << 16) ^
                 (((uint)S[(r1 >> 24) & 255]) << 24) ^ KW[r, 2];
            C3 = S[r3 & 255] ^ (((uint)S[(r0 >> 8) & 255]) << 8) ^ (((uint)S[(r1 >> 16) & 255]) << 16) ^
                 (((uint)S[(r2 >> 24) & 255]) << 24) ^ KW[r, 3];
        }

        private void DecryptBlock(
            uint[,] KW)
        {
            int r;
            uint r0, r1, r2, r3;

            C0 ^= KW[ROUNDS, 0];
            C1 ^= KW[ROUNDS, 1];
            C2 ^= KW[ROUNDS, 2];
            C3 ^= KW[ROUNDS, 3];

            for (r = ROUNDS - 1; r > 1;)
            {
                r0 = Tinv0[C0 & 255] ^ Shift(Tinv0[(C3 >> 8) & 255], 24) ^ Shift(Tinv0[(C2 >> 16) & 255], 16) ^
                     Shift(Tinv0[(C1 >> 24) & 255], 8) ^ KW[r, 0];
                r1 = Tinv0[C1 & 255] ^ Shift(Tinv0[(C0 >> 8) & 255], 24) ^ Shift(Tinv0[(C3 >> 16) & 255], 16) ^
                     Shift(Tinv0[(C2 >> 24) & 255], 8) ^ KW[r, 1];
                r2 = Tinv0[C2 & 255] ^ Shift(Tinv0[(C1 >> 8) & 255], 24) ^ Shift(Tinv0[(C0 >> 16) & 255], 16) ^
                     Shift(Tinv0[(C3 >> 24) & 255], 8) ^ KW[r, 2];
                r3 = Tinv0[C3 & 255] ^ Shift(Tinv0[(C2 >> 8) & 255], 24) ^ Shift(Tinv0[(C1 >> 16) & 255], 16) ^
                     Shift(Tinv0[(C0 >> 24) & 255], 8) ^ KW[r--, 3];
                C0 = Tinv0[r0 & 255] ^ Shift(Tinv0[(r3 >> 8) & 255], 24) ^ Shift(Tinv0[(r2 >> 16) & 255], 16) ^
                     Shift(Tinv0[(r1 >> 24) & 255], 8) ^ KW[r, 0];
                C1 = Tinv0[r1 & 255] ^ Shift(Tinv0[(r0 >> 8) & 255], 24) ^ Shift(Tinv0[(r3 >> 16) & 255], 16) ^
                     Shift(Tinv0[(r2 >> 24) & 255], 8) ^ KW[r, 1];
                C2 = Tinv0[r2 & 255] ^ Shift(Tinv0[(r1 >> 8) & 255], 24) ^ Shift(Tinv0[(r0 >> 16) & 255], 16) ^
                     Shift(Tinv0[(r3 >> 24) & 255], 8) ^ KW[r, 2];
                C3 = Tinv0[r3 & 255] ^ Shift(Tinv0[(r2 >> 8) & 255], 24) ^ Shift(Tinv0[(r1 >> 16) & 255], 16) ^
                     Shift(Tinv0[(r0 >> 24) & 255], 8) ^ KW[r--, 3];
            }

            r0 = Tinv0[C0 & 255] ^ Shift(Tinv0[(C3 >> 8) & 255], 24) ^ Shift(Tinv0[(C2 >> 16) & 255], 16) ^
                 Shift(Tinv0[(C1 >> 24) & 255], 8) ^ KW[r, 0];
            r1 = Tinv0[C1 & 255] ^ Shift(Tinv0[(C0 >> 8) & 255], 24) ^ Shift(Tinv0[(C3 >> 16) & 255], 16) ^
                 Shift(Tinv0[(C2 >> 24) & 255], 8) ^ KW[r, 1];
            r2 = Tinv0[C2 & 255] ^ Shift(Tinv0[(C1 >> 8) & 255], 24) ^ Shift(Tinv0[(C0 >> 16) & 255], 16) ^
                 Shift(Tinv0[(C3 >> 24) & 255], 8) ^ KW[r, 2];
            r3 = Tinv0[C3 & 255] ^ Shift(Tinv0[(C2 >> 8) & 255], 24) ^ Shift(Tinv0[(C1 >> 16) & 255], 16) ^
                 Shift(Tinv0[(C0 >> 24) & 255], 8) ^ KW[r, 3];

            // the final round's table is a simple function of Si so we don't use a whole other four tables for it

            C0 = Si[r0 & 255] ^ (((uint)Si[(r3 >> 8) & 255]) << 8) ^ (((uint)Si[(r2 >> 16) & 255]) << 16) ^
                 (((uint)Si[(r1 >> 24) & 255]) << 24) ^ KW[0, 0];
            C1 = Si[r1 & 255] ^ (((uint)Si[(r0 >> 8) & 255]) << 8) ^ (((uint)Si[(r3 >> 16) & 255]) << 16) ^
                 (((uint)Si[(r2 >> 24) & 255]) << 24) ^ KW[0, 1];
            C2 = Si[r2 & 255] ^ (((uint)Si[(r1 >> 8) & 255]) << 8) ^ (((uint)Si[(r0 >> 16) & 255]) << 16) ^
                 (((uint)Si[(r3 >> 24) & 255]) << 24) ^ KW[0, 2];
            C3 = Si[r3 & 255] ^ (((uint)Si[(r2 >> 8) & 255]) << 8) ^ (((uint)Si[(r1 >> 16) & 255]) << 16) ^
                 (((uint)Si[(r0 >> 24) & 255]) << 24) ^ KW[0, 3];
        }
    }


    internal sealed class Pack
    {
        private Pack()
        {
        }

        internal static void UInt32_To_BE(uint n, byte[] bs)
        {
            bs[0] = (byte)(n >> 24);
            bs[1] = (byte)(n >> 16);
            bs[2] = (byte)(n >> 8);
            bs[3] = (byte)(n);
        }

        internal static void UInt32_To_BE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n);
        }

        internal static uint BE_To_UInt32(byte[] bs)
        {
            uint n = (uint)bs[0] << 24;
            n |= (uint)bs[1] << 16;
            n |= (uint)bs[2] << 8;
            n |= bs[3];
            return n;
        }

        internal static uint BE_To_UInt32(byte[] bs, int off)
        {
            uint n = (uint)bs[off] << 24;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 8;
            n |= bs[++off];
            return n;
        }

        internal static ulong BE_To_UInt64(byte[] bs)
        {
            uint hi = BE_To_UInt32(bs);
            uint lo = BE_To_UInt32(bs, 4);
            return ((ulong)hi << 32) | lo;
        }

        internal static ulong BE_To_UInt64(byte[] bs, int off)
        {
            uint hi = BE_To_UInt32(bs, off);
            uint lo = BE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | lo;
        }

        internal static void UInt64_To_BE(ulong n, byte[] bs)
        {
            UInt32_To_BE((uint)(n >> 32), bs);
            UInt32_To_BE((uint)(n), bs, 4);
        }

        internal static void UInt64_To_BE(ulong n, byte[] bs, int off)
        {
            UInt32_To_BE((uint)(n >> 32), bs, off);
            UInt32_To_BE((uint)(n), bs, off + 4);
        }

        internal static void UInt32_To_LE(uint n, byte[] bs)
        {
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
            bs[2] = (byte)(n >> 16);
            bs[3] = (byte)(n >> 24);
        }

        internal static void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 24);
        }

        internal static uint LE_To_UInt32(byte[] bs)
        {
            uint n = bs[0];
            n |= (uint)bs[1] << 8;
            n |= (uint)bs[2] << 16;
            n |= (uint)bs[3] << 24;
            return n;
        }

        internal static uint LE_To_UInt32(byte[] bs, int off)
        {
            uint n = bs[off];
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 24;
            return n;
        }

        internal static ulong LE_To_UInt64(byte[] bs)
        {
            uint lo = LE_To_UInt32(bs);
            uint hi = LE_To_UInt32(bs, 4);
            return ((ulong)hi << 32) | lo;
        }

        internal static ulong LE_To_UInt64(byte[] bs, int off)
        {
            uint lo = LE_To_UInt32(bs, off);
            uint hi = LE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | lo;
        }

        internal static void UInt64_To_LE(ulong n, byte[] bs)
        {
            UInt32_To_LE((uint)(n), bs);
            UInt32_To_LE((uint)(n >> 32), bs, 4);
        }

        internal static void UInt64_To_LE(ulong n, byte[] bs, int off)
        {
            UInt32_To_LE((uint)(n), bs, off);
            UInt32_To_LE((uint)(n >> 32), bs, off + 4);
        }
    }
}
