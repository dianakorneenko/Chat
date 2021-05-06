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

namespace ChatClient
{
    class Program
    {
        static string userName;
        private const string host = "127.0.0.1";
        private const int port = 8888;
        static TcpClient client;
        static NetworkStream stream;

        static void Main(string[] args)
        {
            BigInteger random = RandomInteger(2048/8);
            Console.WriteLine(random);

            client = new TcpClient();
            try
            {
                client.Connect(host, port); // подключение клиента
                stream = client.GetStream(); // получаем поток


                // получаем p и g от сервера
                BinaryReader reader = new BinaryReader(stream);

                string pString = reader.ReadString();
                BigInteger p = BigInteger.Parse(pString);
                //BigInteger p = new BigInteger(pByte);
                //BigInteger p = FromBigEndian(pByte);
                Console.WriteLine("p: {0}", p);

                BinaryWriter writer = new BinaryWriter(stream);
                writer.Write("gGO");

                string gString = reader.ReadString();
                BigInteger g = BigInteger.Parse(gString);
                Console.WriteLine("g: {0}", g);

                // проверка p и g
                bool gCorrect = CheakG(p, g);
                Console.WriteLine("g correct? - {0}", gCorrect.ToString());
                bool gcorrect = CheakBetween(g, p);
                Console.WriteLine("g correct? - {0}", gcorrect.ToString());

                #region AES256
                //................................................................
                //Console.WriteLine("Enter text that needs to be encrypted..");
                //string data = Console.ReadLine();

                //AesManaged aes = new AesManaged();
                //string hexString = "1234567891234567234567123456781234567823456781234567234578234573";
                //var bytes = new byte[hexString.Length / 2];
                //for (var i = 0; i < 17; i++)
                //{
                //    bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
                //}

                //byte[] key = bytes;

                //hexString = "1234567891234567234567123456781234567823456781234567234578234573";
                //bytes = new byte[hexString.Length / 4];
                //for (var i = 0; i < 9; i++)
                //{
                //    bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
                //}

                //byte[] iv = bytes;

                //byte[] encrypted = Encrypt(data, key, iv);
                //// Print encrypted string    
                //Console.WriteLine($"Encrypted data: {System.Text.Encoding.UTF8.GetString(encrypted)}");
                //// Decrypt the bytes to a string.    
                //string decrypted = Decrypt(encrypted, key, iv);
                //// Print decrypted string. It should be same as raw data    
                //Console.WriteLine($"Decrypted data: {decrypted}");


                //Console.ReadLine();
                //...........................................................
                #endregion

                //Console.Write("Введите свое имя: ");
                //userName = Console.ReadLine();

                // отправляем имя пользователя на сервер
                //writer.Write(userName);

                Console.Write("Введите свое имя: ");

                userName = Console.ReadLine();

                // отправляем имя пользователя на сервер
                writer.Write(userName);

                // генерируем ключ A
                BigInteger A = BigInteger.ModPow(g, random, p);
                Console.WriteLine("A: {0}", A.ToString());
                
                // получаем метку для старта
                string go = reader.ReadString();
                
                Console.WriteLine("go: {0}", go);

                

                // отправляем ключ А на сервер
                writer.Write(A.ToString());
                //writer.Flush();

                // получаем ключ B от второго клиента
                string BString = reader.ReadString();
                BigInteger B = BigInteger.Parse(BString);
                Console.WriteLine("B: {0}", B);

                bool Bcorrect = CheakBetween(B, p);
                Console.WriteLine("B correct? - {0}", Bcorrect.ToString());

                // вычисляем секретный общий ключ K
                BigInteger numberK = BigInteger.ModPow(B, random, p);
                Console.WriteLine("K: {0}", numberK);
                byte[] K = numberK.ToByteArray();
                //using (MemoryStream plaintextBuffer = new MemoryStream(K.Length + 40))
                //{
                //    plaintextBuffer.Write(K, 0, K.Length);
                //    while (plaintextBuffer.Position % 256 != 0)
                //    {
                //        plaintextBuffer.WriteByte(0); // TODO: random padding
                //    }
                //    K = plaintextBuffer.ToArray();
                //}

                string usernameB = reader.ReadString();

                // генерируем ключ и вектор для AES256 
                List<byte[]> keyAndIE = GenerateAES_KeyAndIV_Bytes(K, "plaintext");
                
                byte[] key = keyAndIE[0];
                byte[] iv = keyAndIE[1];

                // начало чата
                // создаем объект чата для получения и передачи зашифрованных сообщений
                Chat chat = new Chat(stream, client, key, iv, usernameB);

                // запускаем новый поток для получения данных
                Thread receiveThread = new Thread(new ThreadStart(chat.ReceiveMessage));
                receiveThread.Start(); //старт потока     
                Console.WriteLine("Добро пожаловать, {0}", userName);
                chat.SendMessage();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Disconnect();
            }
        }

        static bool CheakBetween(BigInteger num, BigInteger p)
        {
            BigInteger limit = new BigInteger(2 ^ (2048 - 64));
            return num > 1 || num < p - 1 || num > limit || num < p - limit;
        }

        static bool CheakG(BigInteger p, BigInteger G)
        {
            int g = Convert.ToInt32(G.ToString());
            switch (g)
            {
                case 2:
                    return p % 8 == 7;
                case 3:
                    return p % 3 == 2;
                case 5:
                    return (p % 5 == 1) || (p % 5 == 4);
                case 6:
                    return (p % 24 == 19) || (p % 24 == 23);
                case 7:
                    return (p % 7 == 3) || (p % 7 == 5) || (p % 7 == 6);
                case 4:
                    return true;
                default:
                    return false;    
            }
        }

        static void EncryptAesManaged(string raw)
        {
            try
            {
                // Create Aes that generates a new key and initialization vector (IV).    
                // Same key must be used in encryption and decryption    
                using (AesManaged aes = new AesManaged())
                {
                    // Encrypt string    
                    byte[] encrypted = Encrypt(raw, aes.Key, aes.IV);
                    // Print encrypted string    
                    Console.WriteLine($"Encrypted data: {System.Text.Encoding.Default.GetString(encrypted)}");
                    // Decrypt the bytes to a string.    
                    string decrypted = Decrypt(encrypted, aes.Key, aes.IV);
                    // Print decrypted string. It should be same as raw data    
                    Console.WriteLine($"Decrypted data: {decrypted}");
                }
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
            Console.ReadKey();
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
        static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
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

        

        //static void ReceiveMessage(NetworkStream stream)
        //{
        //    while (true)
        //    {
        //        try
        //        {
        //            byte[] data = new byte[64]; // буфер для получаемых данных
        //            //string message;
        //            StringBuilder builder = new StringBuilder();
        //            int bytes1 = 0;
        //            AesManaged aes = new AesManaged();
        //            string hexString = "1234567891234567234567123456781234567823456781234567234578234573";
        //            var bytes = new byte[hexString.Length / 2];
        //            for (var i = 0; i < 17; i++)
        //            {
        //                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        //            }

        //            byte[] key = bytes;

        //            hexString = "1234567891234567234567123456781234567823456781234567234578234573";
        //            bytes = new byte[hexString.Length / 4];
        //            for (var i = 0; i < 9; i++)
        //            {
        //                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        //            }

        //            byte[] iv = bytes;
        //            BinaryReader reader = new BinaryReader(stream);
        //            do
        //            {
        //                //byte[] pByte = reader.ReadBytes(32);
                        
        //                bytes1 = stream.Read(data, 0, data.Length);
        //                //Encoding.Unicode.GetBytes(message)
        //                builder.Append(Encoding.Default.GetString(data, 0, bytes1));

        //                //string decrypted = Decrypt(pByte, aes.Key, aes.IV);

        //                //message =  DecryptStringFromBytes(data, key, iv);
        //            }
        //            while (stream.DataAvailable);

        //            string message = builder.ToString();
        //            message = message.Replace($"\0", "");
        //            byte[] mesBytes = Encoding.Default.GetBytes(message);
        //            message = Decrypt(mesBytes, key, iv);
        //            Console.WriteLine(message);//вывод сообщения
        //        }
        //        catch (Exception exp)
        //        {
        //            Console.WriteLine(exp.Message);
        //            Console.WriteLine("Подключение прервано!"); //соединение было прервано
        //            Console.ReadLine();
        //            Disconnect();
        //        }
        //    }
        //}

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

        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        static List<byte[]> GenerateAES_KeyAndIV_Bytes(byte[] key, string plaintext)
        {
            SHA256Managed hash = new SHA256Managed();

            //byte[] key = keyInt.ToByteArray();
            byte[] plainttextBytes = Encoding.Default.GetBytes(plaintext);
            byte[] subKey = new byte[32 + plainttextBytes.Length];
            Buffer.BlockCopy(key, 88+8, subKey, 0, 32);
            Buffer.BlockCopy(plainttextBytes, 0, subKey, 32, plainttextBytes.Length);
            using (MemoryStream plaintextBuffer = new MemoryStream(subKey.Length + 40))
            {
                plaintextBuffer.Write(subKey, 0, subKey.Length);
                while (plaintextBuffer.Position % 16 != 0)
                {
                    plaintextBuffer.WriteByte(0); // TODO: random padding
                }
                subKey = plaintextBuffer.ToArray();
            }
            //string text = subKey + "простойтекст". + "рандомные символы";
            byte[] msg_key_large = hash.ComputeHash(subKey);
            byte[] msg_key = new byte[16];
            Buffer.BlockCopy(msg_key_large, 8, msg_key, 0, 16);
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
            byte[] aes_key = new byte[8+16+8];
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

        //static string[] GenerateAES_KeyAndIV(BigInteger key)
        //{
        //    string subKey = key.ToString().Substring(88 + 8, 32);
        //    string text = subKey + "простойтекст" + "рандомные символы";
        //    string msg_key_large = getHashSha256(text);
        //    string msg_key = msg_key_large.Substring( 8, 16);
        //    string sha256_a = getHashSha256(msg_key + key.ToString().Substring(8, 36));
        //    string sha256_b = getHashSha256(key.ToString().Substring(40 + 8, 36) + msg_key);
        //    string aes_key = (sha256_a.Substring( 0, 8) + sha256_b.Substring( 8, 16) + sha256_a.Substring( 24, 8));
        //    string aes_iv = sha256_b.Substring(0, 8) + sha256_a.Substring(8, 16) + sha256_b.Substring(24, 8);
        //    return new string[] { aes_key, aes_iv} ;
        //}

        public static byte[] getHashSha256(string text)
        {
            byte[] bytes = Encoding.Default.GetBytes(text);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            //string hashString = string.Empty;
            //foreach (byte x in hash)
            //{
            //    hashString += String.Format("{0:x2}", x);
            //}
            return hash;
            //return hash.ToString();
        }

        static BigInteger RandomInteger(int size)
        {
            using (var generator = RandomNumberGenerator.Create())
            {
                var salt = new byte[size];
                generator.GetBytes(salt);
                BigInteger number = FromBigEndian(salt);
                return number;
            }
        }

        public static BigInteger FromBigEndian(byte[] p)
        {
            return new BigInteger((p.Reverse().Concat(new byte[] { 0 })).ToArray());
        }

        // чтение входящего сообщения и преобразование в строку
        private static BigInteger GetMessage()
        {
            byte[] data = new byte[256]; // буфер для получаемых данных
            //StringBuilder builder = new StringBuilder();
            int bytes = 0;
            BigInteger num;
            do
            {
                bytes = stream.Read(data, 0, data.Length);
                //builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                num = FromBigEndian(data);
            }
            while (stream.DataAvailable);

            //return builder.ToString();
            return num;
        }

        private static BigInteger GetMessage2()
        {
            byte[] data = new byte[256]; // буфер для получаемых данных
            //StringBuilder builder = new StringBuilder();
            int bytes = 0;
            BigInteger num;
            do
            {
                bytes = stream.Read(data, 0, data.Length);
                //builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                num = new BigInteger(bytes);
            }
            while (stream.DataAvailable);

            //return builder.ToString();
            return num;
        }

        static void Disconnect()
        {
            if (stream != null)
                stream.Close();//отключение потока
            if (client != null)
                client.Close();//отключение клиента
            Environment.Exit(0); //завершение процесса
        }


        //...........................................................................................................

        // тест Миллера — Рабина на простоту числа
        // производится k раундов проверки числа n на простоту
        public static bool MillerRabinTest(BigInteger n, int k)
        {
            // если n == 2 или n == 3 - эти числа простые, возвращаем true
            if (n == 2 || n == 3)
                return true;

            // если n < 2 или n четное - возвращаем false
            if (n < 2 || n % 2 == 0)
                return false;

            // представим n − 1 в виде (2^s)·t, где t нечётно, это можно сделать последовательным делением n - 1 на 2
            BigInteger t = n - 1;

            int s = 0;

            while (t % 2 == 0)
            {
                t /= 2;
                s += 1;
            }

            // повторить k раз
            for (int i = 0; i < k; i++)
            {
                // выберем случайное целое число a в отрезке [2, n − 2]
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

                byte[] _a = new byte[n.ToByteArray().LongLength];

                BigInteger a;

                do
                {
                    rng.GetBytes(_a);
                    a = new BigInteger(_a);
                }
                while (a < 2 || a >= n - 2);

                // x ← a^t mod n, вычислим с помощью возведения в степень по модулю
                BigInteger x = BigInteger.ModPow(a, t, n);

                // если x == 1 или x == n − 1, то перейти на следующую итерацию цикла
                if (x == 1 || x == n - 1)
                    continue;

                // повторить s − 1 раз
                for (int r = 1; r < s; r++)
                {
                    // x ← x^2 mod n
                    x = BigInteger.ModPow(x, 2, n);

                    // если x == 1, то вернуть "составное"
                    if (x == 1)
                        return false;

                    // если x == n − 1, то перейти на следующую итерацию внешнего цикла
                    if (x == n - 1)
                        break;
                }

                if (x != n - 1)
                    return false;
            }

            // вернуть "вероятно простое"
            return true;
        }


        public static void Prime(BigInteger number)
        {
            int devisors = 0;
            for (int i = 2; i <= number; i++)
                if (number % i == 0)
                {
                    devisors++;
                }

            if (number != 1 && devisors == 1)
                Console.WriteLine("prime");
            else
                Console.WriteLine("not prime");
        }

        // отправка сообщений
        //static void SendMessage(byte[] key, byte[] iv)
        //{
        //    Console.WriteLine("Введите сообщение: ");

        //    while (true)
        //    {
        //        string message = Console.ReadLine();
        //        byte[] data = EncryptStringToBytes(message, key, iv);
        //        stream.Write(data, 0, data.Length);
        //    }
        //}

        // получение сообщений
        //static void ReceiveMessage(byte[] key, byte[] iv)
        //{
        //    while (true)
        //    {
        //        try
        //        {
        //            byte[] data = new byte[64]; // буфер для получаемых данных
        //            string message;
        //            int bytes = 0;
        //            do
        //            {
        //                bytes = stream.Read(data, 0, data.Length);
        //                message = DecryptStringFromBytes(data, key, iv);
        //            }
        //            while (stream.DataAvailable);

        //            Console.WriteLine(message);//вывод сообщения
        //        }
        //        catch
        //        {
        //            Console.WriteLine("Подключение прервано!"); //соединение было прервано
        //            Console.ReadLine();
        //            Disconnect();
        //        }
        //    }
        //}


    }

}
