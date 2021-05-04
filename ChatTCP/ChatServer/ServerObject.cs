using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Linq;
using System.Numerics;
using System.IO;

namespace ChatServer
{
    public class ServerObject
    {
        static TcpListener tcpListener; // сервер для прослушивания
        public List<ClientObject> clients = new List<ClientObject>(); // все подключения
        

        protected internal void AddConnection(ClientObject clientObject)
        {
            clients.Add(clientObject);
        }
        protected internal void RemoveConnection(string id)
        {
            // получаем по id закрытое подключение
            ClientObject client = clients.FirstOrDefault(c => c.Id == id);
            // и удаляем его из списка подключений
            if (client != null)
                clients.Remove(client);
        }
        // прослушивание входящих подключений
        protected internal void Listen()
        {
            try
            {
                tcpListener = new TcpListener(IPAddress.Any, 8888);
                tcpListener.Start();
                Console.WriteLine("Сервер запущен. Ожидание подключений...");
                TcpClient tcpClient;
                ClientObject clientObject;

                while (true)
                {
                    tcpClient = tcpListener.AcceptTcpClient();
                    clientObject = new ClientObject(tcpClient, this);

                    clientObject.KeyGen();
                    Console.WriteLine("ждем подключения второго пользователя");
                    if (clients.Count > 1)
                        break;
                }
                
                Console.WriteLine("пользователи подключились");

                string A = clients[0].GetA();
                string B = clients[1].GetA();

                this.BroadcastMessage(A, clients[0].Id);
                this.BroadcastMessage(B, clients[1].Id);

                Thread clientThread1 = new Thread(new ThreadStart(clients[0].Process));
                clientThread1.Start();
                Thread clientThread2 = new Thread(new ThreadStart(clients[1].Process));
                clientThread2.Start();

                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Disconnect();
            }
        }

        // трансляция A подключенным клиентам
        protected internal void BroadcastMessage(byte[] message, string id)
        {

            for (int i = 0; i < clients.Count; i++)
            {
                if (clients[i].Id != id) // если id клиента не равно id отправляющего
                {
                    BinaryWriter writer = new BinaryWriter(clients[i].Stream);
                    writer.Write(message); //передача данных
                }
            }
        }

        // трансляция сообщения подключенным клиентам
        protected internal void BroadcastMessage(string message, string id)
        {
            
            byte[] data = Encoding.Unicode.GetBytes(message);
            for (int i = 0; i < clients.Count; i++)
            {
                BinaryWriter writer = new BinaryWriter(clients[i].Stream);
                if (clients[i].Id != id) // если id клиента не равно id отправляющего
                {
                    writer.Write(message);
                    //clients[i].Stream.Write(data, 0, data.Length); //передача данных
                }
            }
        }
        // отключение всех клиентов
        protected internal void Disconnect()
        {
            tcpListener.Stop(); //остановка сервера

            for (int i = 0; i < clients.Count; i++)
            {
                clients[i].Close(); //отключение клиента
            }
            Environment.Exit(0); //завершение процесса
        }
    }
}
