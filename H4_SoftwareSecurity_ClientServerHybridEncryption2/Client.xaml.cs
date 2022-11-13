using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
namespace H4_SoftwareSecurity_ClientServerHybridEncryption2
{
    /// <summary>
    /// Interaction logic for Client.xaml
    /// </summary>
    public partial class Client : Page
    {
        static int port = 1234;
        static TcpClient tcpClient = new TcpClient("localhost", port);
        static NetworkStream stream = tcpClient.GetStream();
        StreamReader reader = new StreamReader(stream);
        StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };

        MyRSA rsa = new MyRSA();

        SymmetricAlgorithm mySymmetricAlg;

        public string latestMessage;

        public string serverKey;
        public string serverIV;


        public Client()
        {
            InitializeComponent();
            WriteLine("Starting client...");
            WriteLine("Enter text to send: ");
        }

        private void SendButton_Click(object sender, RoutedEventArgs e)
        {
            if (InputContainer.Text != "")
            {
                SendMessage(InputContainer.Text);
            }
        }

        private void GenerateRSAKeysButton_Click(object sender, RoutedEventArgs e)
        {
            Tuple<string, string> keyPair = rsa.GenerateNewKeys();
            PrivateKeyContainer.Text = keyPair.Item1;
            PublicKeyContainer.Text = keyPair.Item2;
        }

        private void SendPublicKeyButton_Click(object sender, RoutedEventArgs e)
        {
            if (PublicKeyContainer.Text != "")
            {
                SendMessage(PublicKeyContainer.Text);
            }
        }

        private void RSADecryptLatestMessageButton_Click(object sender, RoutedEventArgs e)
        {
            latestMessage = rsa.Decrypt(PrivateKeyContainer.Text, Convert.FromBase64String(latestMessage));

            DivideString();
            KeyContainer.Text = serverKey;
            IVContainer.Text = serverIV;

            WriteLine(latestMessage);

            SetUpAES();
        }
        private void AESDecryptLatestMessageButton_Click(object sender, RoutedEventArgs e)
        {
            string decryptedMessage = AESDecrypt(latestMessage);

            WriteLine(decryptedMessage);
        }

        private void SendAESEncryptedMessageButton_Click(object sender, RoutedEventArgs e)
        {
            string message = AESEncrypt(InputContainer.Text);

            SendMessage(message);
        }

        void DivideString()
        {
            serverKey = latestMessage.Substring(0, 24);
            serverIV = latestMessage.Substring(24, 24);
        }

        void SetUpAES()
        {
            mySymmetricAlg = Aes.Create();
            mySymmetricAlg.KeySize = 128;
            mySymmetricAlg.Key = Convert.FromBase64String(serverKey);
            mySymmetricAlg.IV = Convert.FromBase64String(serverIV);
            mySymmetricAlg.Mode = CipherMode.ECB;
            mySymmetricAlg.Padding = PaddingMode.PKCS7;

            WriteLine("AES is ready");
        }

        void SendMessage(string message)
        {
            string lineToSend = message;
            WriteLine("Client: " + lineToSend);
            writer.WriteLine(lineToSend);
            GetServerResponse();
        }

        void GetServerResponse()
        {
            string lineReceived = reader.ReadLine();
            latestMessage = lineReceived;
            WriteLine("Server: " + lineReceived);
        }

        void WriteLine(string output)
        {
            LogContainer.Text += output.ToString() + "\n";
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