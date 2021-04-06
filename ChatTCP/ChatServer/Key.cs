using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Numerics;

namespace ChatServer
{
    public class Key
    {
        public Key(BigInteger p, BigInteger g, string username)
        {
            this.Id = Guid.NewGuid().ToString();
            this.UserName = username;
            this.p = p;
            this.g = g;
        }

        public string Id { get; private set; }
        public string UserName { get; private set; }
        public BigInteger p { get; private set; }
        public BigInteger g { get; private set; }
        
    }

}

