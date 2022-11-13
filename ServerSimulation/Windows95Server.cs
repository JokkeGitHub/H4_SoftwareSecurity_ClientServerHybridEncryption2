using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ServerSimulation
{
    public class Windows95Server
    {
        SymmetricAlgorithm mySymmetricAlg;

        static int port = 1234;
        static TcpListener listener = new TcpListener(IPAddress.Loopback, port);

        public string clientPublicKey;

        public int phase = 0;

        public void Boot()
        {
            mySymmetricAlg = Aes.Create();
            mySymmetricAlg.KeySize = 128;
            mySymmetricAlg.Mode = CipherMode.ECB;
            mySymmetricAlg.Padding = PaddingMode.PKCS7;
            mySymmetricAlg.GenerateIV();
            mySymmetricAlg.GenerateKey();

            listener.Start();

            TcpClient client = listener.AcceptTcpClient();
            NetworkStream stream = client.GetStream();
            StreamWriter writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };
            StreamReader reader = new StreamReader(stream, Encoding.ASCII);

            while (true)
            {
                string inputLine = "";
                while (inputLine != null)
                {
                    inputLine = reader.ReadLine();
                    Console.WriteLine("Client: " + inputLine);
                    writer.WriteLine(Response(inputLine));
                }
                Console.WriteLine("Server saw disconnect from client.");
            }
        }

        string Response(string inputLine)
        {
            string response = "";

            AnalyzeInput(inputLine);

            if (phase == 0)
            {
                response = "Requesting Encryption";
                Console.WriteLine("Server: " + response);
            }
            else if (phase == 1)
            {
                response = Convert.ToBase64String(mySymmetricAlg.Key);
                response += Convert.ToBase64String(mySymmetricAlg.IV);

                response = Convert.ToBase64String(RSAEncrypt(clientPublicKey, response));

                Console.WriteLine("Server: " + response);

                phase = 2;
            }
            else if (phase == 2)
            {
                string echo = AESDecrypt(inputLine);
                Console.WriteLine(echo);

                response = AESEncrypt(echo);
            }

            return response;
        }

        void AnalyzeInput(string inputLine)
        {
            if (inputLine.StartsWith("<RSAKeyValue>") == true)
            {
                clientPublicKey = inputLine;
                phase = 1;
            }
        }

        public byte[] RSAEncrypt(string publicKeyXML, string dataToEncrypt)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKeyXML);

            return rsa.Encrypt(ASCIIEncoding.ASCII.GetBytes(dataToEncrypt), true);
        }

        public string AESEncrypt(string plainText)
        {
            ICryptoTransform transform = mySymmetricAlg.CreateEncryptor();
            byte[] encryptedBytes = transform.TransformFinalBlock(ASCIIEncoding.ASCII.GetBytes(plainText), 0, plainText.Length);
            string encryptedText = Convert.ToBase64String(encryptedBytes);

            return encryptedText;
        }

        public string AESDecrypt(string cipherText)
        {
            ICryptoTransform transform = mySymmetricAlg.CreateDecryptor();
            byte[] encryptedBytes = Convert.FromBase64String(cipherText);
            byte[] decryptedBytes = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            string decryptedText = ASCIIEncoding.ASCII.GetString(decryptedBytes);

            return decryptedText;
        }
    }
}