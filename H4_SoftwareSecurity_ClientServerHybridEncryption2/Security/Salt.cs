using System.Security.Cryptography;

namespace H4_SoftwareSecurity_ClientServerHybridEncryption2
{
    internal class Salt
    {
        public const int saltSize = 32;

        public static byte[] GenerateSalt()
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] randomNumber = new byte[saltSize];
                rng.GetBytes(randomNumber);

                return randomNumber;
            }
        }
    }
}
