using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace AuthSystemPasswordService
{
    public struct KeyDerivationParameters
    {
        public KeyDerivationPrf DerivationFunction { get; }

        public IterationCount IterationCount { get; }

        public SaltLength SaltLength { get; }

        public KeyLength KeyLength { get; }

        public KeyDerivationParameters(KeyDerivationPrf derivationFunction, IterationCount iterationCount,
            SaltLength saltLength, KeyLength keyLength)
        {
            DerivationFunction = derivationFunction;
            IterationCount = iterationCount;
            SaltLength = saltLength;
            KeyLength = keyLength;
        }
    }
}
