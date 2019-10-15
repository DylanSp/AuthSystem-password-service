using AuthSystemPasswordService.Interfaces;
using System.Security.Cryptography;

namespace AuthSystemPasswordService.Services
{
    public class CryptoRng : ICryptoRng
    {
        private RandomNumberGenerator Generator { get; }

        public CryptoRng()
        {
            Generator = RandomNumberGenerator.Create();
        }

        public byte[] GetRandomBytes(int numBytes)
        {
            var bytes = new byte[numBytes];
            Generator.GetBytes(bytes);
            return bytes;
        }
    }
}
