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
        //static BigInteger p = FromBigEndian(pByte);
        //BigInteger 30338441306710824804516959109098181086855192952135019189851181168307791957998938970265963004689494729710556511356229841738960984901765261698546792603125677062688381218858928771483484633276857536990003838336664410103178815773882514537820950485140466016900720094128702655262917948587398291884951230690571653636669353815234114024146878312465109145305132403179927027445993122924437380653943930479813978934453164935952440770645115130245613849671021815612619676107239553173920288572561324153982244928568395675690202793108354696667701899214475172652784287168253406855934274249534267057837241381398284714744283774708513553007;
        //static BigInteger g = GenerateG(p);
        //static BigInteger g = 2;
        static string gString = "2";
        //2
        //static string bitSring = "11110000010100111010010111000001111011100101111111010010111011000101010100010100010100101010010111110111011100111100001101100000100110001001011010101010101000011011110011010111010010111101000010010111010110011000110110110000010101010010011111001100111001101100010101011010111000001000010000111010101111101000100010101111011001011101111000000011000110011101001111001100110010001111000011001110011000111010111101110000101110101011010101101110110100010101000010101111111011110000111001111011001011011111101111100100100101001100010100000000000101001001110100010010011101110111110010010000001111010000011110111100010100100000001110000111000000111010110010110111110101110100101110000110010011001000101100001000000011001010110000111011011101111101101010111110011101011001111100010111111001101010111100001010000011011001000000101011001001100010110011110100000111011110010111101001011011001110010011001110000011011110101011111000010010101000111110001110001001100101001010100100110000110100110010000010000101111110111111000010111110000111100101001011101100010101101010100111000101110001001000011001101110010111111011111100111001101101011110100111010011110011100001111001001110110101001010100000100001101000111111000101001010010110011101100011101000111000001110111110101101111001000100110001111010001110101001011000001000001111001101100001111011111100001111101010110100100111001110000110101001011100001101100111110101000000110001000010011001101011011001001000001100011000001010100000100000100110100111011000010100011001010010110011010001011011011000110010101100011111000100000110011101101110101111000100010101011101010010101110110001011001111011101010111011011101101001101000001001011010010101101001000001101000011110101011100011100011000010101010010011111111101100011100110011101100101110110101100110111000010010111110100010101111110001111011101100001100000001110011010111011111010111110101111011101000011001011101000110011011100100011100100000011010101010110100011101000110111110000000000000010101110101110100001011011011111111111010000100001011101001101111";
        static string pString = "30338441306710824804516959109098181086855192952135019189851181168307791957998938970265963004689494729710556511356229841738960984901765261698546792603125677062688381218858928771483484633276857536990003838336664410103178815773882514537820950485140466016900720094128702655262917948587398291884951230690571653636669353815234114024146878312465109145305132403179927027445993122924437380653943930479813978934453164935952440770645115130245613849671021815612619676107239553173920288572561324153982244928568395675690202793108354696667701899214475172652784287168253406855934274249534267057837241381398284714744283774708513553007";
        //static BigInteger p = BigInteger.Parse(hexString);
        
        //static BigInteger p = GetP(hexString);
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
                Stream = client.GetStream();


                BinaryWriter writer = new BinaryWriter(Stream);

                // отправили p пользователю

                Console.WriteLine("p: {0}", pString);
                writer.Write(pString);

                BinaryReader reader = new BinaryReader(Stream);
                string gGo = reader.ReadString();
                Console.WriteLine(gGo);

                // отправили g пользователю
                Console.WriteLine("g: {0}", gString);
                writer.Write(gString);
                writer.Flush();

                // получили имя пользователя
                //BinaryReader reader = new BinaryReader(Stream);
                userName = reader.ReadString();
                Console.WriteLine(userName);
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

        public string GetA()
        {
            try
            {
                Console.WriteLine("начался метод GetA");
                
                // отправляем метку для старта
                BinaryWriter writer = new BinaryWriter(Stream);
                writer.Write("Run");

                // получаем A пользователя
                BinaryReader reader = new BinaryReader(Stream);
                string AString = reader.ReadString();
                Console.WriteLine("A: {0}", AString);
                
                return AString;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return e.Message;
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


                byte[] messageByte;
                string message;
                Console.WriteLine("Бесконечный цикл чата");
                while (true)
                {
                    try
                    {
                        messageByte = GetMessageFromChat();
                        //message = String.Format("{0}: {1}", userName, message);
                        //Console.WriteLine(message);
                        server.BroadcastMessage(messageByte, this.Id);
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

        // чтение входящего сообщения из чата
        private byte[] GetMessageFromChat()
        {
            byte[] data = new byte[64]; // буфер для получаемых данных
            int bytes = 0;
            do
            {
                bytes = Stream.Read(data, 0, data.Length);
            }
            while (Stream.DataAvailable);

            return data;
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
