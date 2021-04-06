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
                Console.WriteLine("получаем клиента и поток");
                client.Connect(host, port); //подключение клиента
                stream = client.GetStream(); // получаем поток

                Console.WriteLine("Этап 2");
                BinaryReader reader = new BinaryReader(stream);
                byte[] pByte = reader.ReadBytes(256);
                BigInteger p = FromBigEndian(pByte);
                Console.WriteLine("p: {0}", p);
                byte[] gByte = reader.ReadBytes(1);
                BigInteger g = new BigInteger(gByte);
                Console.WriteLine("g: {0}", g);

                Console.WriteLine("Этап 3");
                Console.Write("Введите свое имя: ");
                userName = Console.ReadLine();
                BinaryWriter writer = new BinaryWriter(stream);
                writer.Write(userName);
                BigInteger A = BigInteger.ModPow(g, random, p);
                Console.WriteLine("A: {0}", A);

                
                string go = reader.ReadString();
                Console.WriteLine("go: {0}", go);
                
                writer.Write(A.ToByteArray());
                writer.Flush();


                byte[] Bbyte = reader.ReadBytes(256);
                BigInteger B = new BigInteger(Bbyte);
                Console.WriteLine("B: {0}", B);

                reader.Close();
                writer.Close();


                //Console.ReadLine();

                // запускаем новый поток для получения данных
                Thread receiveThread = new Thread(new ThreadStart(ReceiveMessage));
                receiveThread.Start(); //старт потока     
                Console.WriteLine("Добро пожаловать, {0}", userName);
                SendMessage();
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

        public static BigInteger FromBigEndian(byte[] p)
        {
            return new BigInteger((p.Reverse().Concat(new byte[] { 0 })).ToArray());
        }

        // отправка сообщений
        static void SendMessage()
        {
            Console.WriteLine("Введите сообщение: ");

            while (true)
            {
                string message = Console.ReadLine();
                byte[] data = Encoding.Unicode.GetBytes(message);
                stream.Write(data, 0, data.Length);
            }
        }

        // получение сообщений
        static void ReceiveMessage()
        {
            while (true)
            {
                try
                {
                    byte[] data = new byte[64]; // буфер для получаемых данных
                    StringBuilder builder = new StringBuilder();
                    int bytes = 0;
                    do
                    {
                        bytes = stream.Read(data, 0, data.Length);
                        builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                    }
                    while (stream.DataAvailable);

                    string message = builder.ToString();
                    Console.WriteLine(message);//вывод сообщения
                }
                catch
                {
                    Console.WriteLine("Подключение прервано!"); //соединение было прервано
                    Console.ReadLine();
                    Disconnect();
                }
            }
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
    }
}
