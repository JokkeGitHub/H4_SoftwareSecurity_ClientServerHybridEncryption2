using System;
using System.Security.Cryptography;
using System.Text;

namespace H4_SoftwareSecurity_ClientServerHybridEncryption2
{
    internal class MyRSA
    {
        RSACryptoServiceProvider rsa = null;
        string publicPrivateKeyXML;
        string publicOnlyKeyXML;

        public Tuple<string, string> GenerateNewKeys()
        {
            RSA rsa = new RSACryptoServiceProvider(4096);

            publicPrivateKeyXML = rsa.ToXmlString(true);

            publicOnlyKeyXML = rsa.ToXmlString(false);

            Tuple<string, string> keyPair = Tuple.Create(publicPrivateKeyXML, publicOnlyKeyXML);

            return keyPair;
        }

        public byte[] Encrypt(string publicKeyXML, string dataToEncrypt)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKeyXML);

            return rsa.Encrypt(ASCIIEncoding.ASCII.GetBytes(dataToEncrypt), true);
        }

        public string Decrypt(string publicPrivateKeyXML, byte[] encryptedData)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicPrivateKeyXML);

            return ASCIIEncoding.ASCII.GetString(rsa.Decrypt(encryptedData, true));
        }
    }
}
