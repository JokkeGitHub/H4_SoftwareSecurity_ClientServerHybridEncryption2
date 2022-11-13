namespace H4_SoftwareSecurity_ClientServerHybridEncryption2
{
    internal class User
    {
        public string UserName { get; set; }
        public byte[] Salt { get; set; }
        public byte[] Hash { get; set; }

        public User(string userName, byte[] salt, byte[] hash)
        {
            UserName = userName;
            Salt = salt;
            Hash = hash;
        }
    }
}
