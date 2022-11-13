using System.Text;
using System.Windows;

namespace H4_SoftwareSecurity_ClientServerHybridEncryption2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public int LoginAttemptsLeft = 5;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void OnClick_LoginAttempt(object sender, RoutedEventArgs e)
        {
            string username = UsernameLogin.Text;
            string password = PasswordLogin.Text;

            LoginAttempt(username, password);
        }

        private void LoginAttempt(string username, string password)
        {
            bool usernameExists = DatabaseConnection.CheckUsername(username);

            if (usernameExists == false)
            {
                MessageBox.Show("User doesn't exist");
            }
            else if (usernameExists == true)
            {
                ComparePassword(username, password);
            }
            else
            {
                MessageBox.Show("Something went wrong, try again");
            }
        }

        private void ComparePassword(string username, string password)
        {
            bool passwordValidated = PasswordChecker.Validate(username, password);

            if (passwordValidated == true)
            {
                MessageBox.Show("You have successfully logged in");
                ResaltAndRehash(username, password);
                Client client = new Client();
                this.Content = client;
            }
            else if (passwordValidated == false)
            {
                MessageBox.Show("Wrong password");
                LoginAttemptsLeft--;
                CheckLoginAttempts();
            }
            else
            {
                MessageBox.Show("Something went wrong, try again");
            }
        }

        private void CheckLoginAttempts()
        {
            if (LoginAttemptsLeft <= 0)
            {
                MessageBox.Show("You have been locked out by the system");
                this.Close();
            }
        }

        private void ResaltAndRehash(string username, string password)
        {
            byte[] encodedPassword = Encoding.UTF8.GetBytes(password);
            byte[] salt = Salt.GenerateSalt();
            byte[] hash = Hash.HashPassword(encodedPassword, salt);

            DatabaseConnection.UpdateSaltAndHash(username, salt, hash);
        }

        private void OnClick_CreateUser(object sender, RoutedEventArgs e)
        {
            string username = UsernameCreate.Text;
            string password = PasswordCreate.Text;

            CreateUser(username, password);
        }

        private void CreateUser(string username, string password)
        {
            bool usernameExists = DatabaseConnection.CheckUsername(username);

            if (usernameExists == true)
            {
                MessageBox.Show("Username already exists");
            }
            else if (usernameExists == false)
            {
                User newUser = UserFactory.Create(username, password);
                DatabaseConnection.CreateUser(newUser);
                MessageBox.Show("User successfully created");
            }
            else
            {
                MessageBox.Show("Something went wrong, try again");
            }
        }
    }
}
