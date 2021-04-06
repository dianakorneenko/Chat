using System;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using System.Numerics;
using System.IO;

namespace ChatServer
{
    public class ClientObject
    {
        protected internal string Id { get; private set; }
        protected internal NetworkStream Stream { get; private set; }
        string userName;
        TcpClient client;
        ServerObject server; // объект сервера

        static byte[] pByte = GeneratePrime();
        static BigInteger p = FromBigEndian(pByte);
        static BigInteger g = GenerateG(p);
        
        public ClientObject(TcpClient tcpClient, ServerObject serverObject)
        {
            Id = Guid.NewGuid().ToString();
            client = tcpClient;
            server = serverObject;
            serverObject.AddConnection(this);
        }

        public void KeyGen()
        {
            try
            {
                Console.WriteLine("начался метод KeyGen");
                Stream = client.GetStream();
                Console.WriteLine("запущен поток для клиента");

                Console.WriteLine("прочитали1");
                BinaryWriter writer = new BinaryWriter(Stream);
                Console.WriteLine("p: {0}", p);
                writer.Write(pByte);
                Console.WriteLine("g: {0}", g);
                writer.Write(g.ToByteArray());
                writer.Flush();
                BinaryReader reader = new BinaryReader(Stream);
                userName = reader.ReadString();
                Console.WriteLine(userName);

                //Console.WriteLine("прочитали2");
                //byte[] AByte = reader.ReadBytes(256);
                //Console.WriteLine("прочитали3");

                //writer.Close();
                //reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                // в случае выхода из цикла закрываем ресурсы
                //server.RemoveConnection(this.Id);
                //Close();
            }
        }

        public byte[] GetA()
        {
            try
            {
                Console.WriteLine("начался метод GetA");
                //Stream = client.GetStream();
                //Console.WriteLine("запущен поток для клиента");

                BinaryWriter writer = new BinaryWriter(Stream);
                Console.WriteLine("отправляем RUN");
                writer.Write("Run");

                BinaryReader reader = new BinaryReader(Stream);
                byte[] AByte = reader.ReadBytes(256);
                BigInteger A = new BigInteger(AByte);
                Console.WriteLine("A: {0}", A);
                Console.WriteLine("получили А");
                
                //server.BroadcastMessage(AByte, this.Id);

                //reader.Close();
                return AByte;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return new byte[0];
            }
            finally
            {
                // в случае выхода из цикла закрываем ресурсы
                //server.RemoveConnection(this.Id);
                //Close();
            }
        }

        public void Process()
        {
            try
            {
                Console.WriteLine("начался метод Process");


                string message;
                Console.WriteLine("бесконечный цикл");
                while (true)
                {
                    try
                    {
                        message = GetMessage();
                        message = String.Format("{0}: {1}", userName, message);
                        Console.WriteLine(message);
                        server.BroadcastMessage(message, this.Id);
                    }
                    catch
                    {
                        message = String.Format("{0}: покинул чат", userName);
                        Console.WriteLine(message);
                        server.BroadcastMessage(message, this.Id);
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                // в случае выхода из цикла закрываем ресурсы
                server.RemoveConnection(this.Id);
                Close();
            }
        }

        // чтение входящего сообщения и преобразование в строку
        private string GetMessage()
        {
            byte[] data = new byte[64]; // буфер для получаемых данных
            StringBuilder builder = new StringBuilder();
            int bytes = 0;
            do
            {
                bytes = Stream.Read(data, 0, data.Length);
                builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
            }
            while (Stream.DataAvailable);

            return builder.ToString();
        }

        // закрытие подключения
        protected internal void Close()
        {
            if (Stream != null)
                Stream.Close();
            if (client != null)
                client.Close();
        }

        //криптография -----------------------------------------------------------------------------
        static byte[] GeneratePrime()
        {
            //lets take a new CSP with a new 2048 bit rsa key pair
            var csp = new RSACryptoServiceProvider(2 * 2048);
            //and the public key ...
            var pubKey = csp.ExportParameters(true).P;

            //BigInteger primeP = FromBigEndian(pubKey);
            //Console.WriteLine(primeP);
            //bool Mp = MillerRabinTest(primeP, 10);
            //Console.WriteLine(Mp);
            return pubKey;
        }

        public static BigInteger FromBigEndian(byte[] p)
        {
            return new BigInteger((p.Reverse().Concat(new byte[] { 0 })).ToArray());
        }

        static BigInteger GenerateG(BigInteger P)
        {
            if (P % 8 == 7)
                return 2;
            if (P % 3 == 2)
                return 3;
            if (P % 5 == 1 || P % 5 == 4)
                return 5;
            if (P % 24 == 19 || P % 24 == 23)
                return 6;
            if (P % 7 == 3 || P % 7 == 5 || P % 7 == 6)
                return 7;
            return 4;
        }
    }
}
