using System;
using System.Data;
using System.Data.SqlClient;
using System.Windows;

namespace H4_SoftwareSecurity_ClientServerHybridEncryption2
{
    internal class DatabaseConnection
    {

        static SqlConnection connection = new SqlConnection("Data Source=ZBC-AA-JOAC3146;Initial Catalog=SecurePassword;Integrated Security=True;Connect Timeout=30;Encrypt=False;TrustServerCertificate=False;ApplicationIntent=ReadWrite;MultiSubnetFailover=False");

        public static bool CheckUsername(string username)
        {
            bool usernameExists = false;

            try
            {
                connection.Open();
                SqlCommand cmd = connection.CreateCommand();

                cmd.CommandType = CommandType.Text;
                cmd.CommandText = @"SELECT (username) FROM UserDB WHERE (username) = (@username);";
                cmd.Parameters.AddWithValue("@username", username);
                cmd.ExecuteNonQuery();

                DataTable dataTable = new DataTable();
                SqlDataAdapter dataAdapter = new SqlDataAdapter(cmd);

                dataAdapter.Fill(dataTable);
                foreach (DataRow dataRow in dataTable.Rows)
                {
                    if (dataRow["username"].ToString() == username)
                    {
                        usernameExists = true;
                    }
                }

                connection.Close();
            }
            catch (Exception)
            {
                MessageBox.Show("Something went wrong");
            }
            return usernameExists;
        }

        public static void CreateUser(User user)
        {
            string decodedSalt = Convert.ToBase64String(user.Salt);
            string decodedHash = Convert.ToBase64String(user.Hash);

            try
            {
                SqlCommand cmd = new SqlCommand();

                cmd.Connection = connection;

                cmd.CommandText = @"INSERT INTO UserDB(username, salt, hash) VALUES (@username, @salt, @hash)";
                cmd.Parameters.AddWithValue("@username", user.UserName);
                cmd.Parameters.AddWithValue("@salt", decodedSalt);
                cmd.Parameters.AddWithValue("@hash", decodedHash);

                connection.Open();
                SqlDataReader reader = cmd.ExecuteReader();
                connection.Close();
            }
            catch (Exception)
            {
                MessageBox.Show("Something went wrong USER NAME COMPARISON");
            }
        }

        public static byte[] GetSalt(string username)
        {
            byte[] salt = { 0, 0, 0, 0 };

            try
            {
                connection.Open();
                SqlCommand cmd = connection.CreateCommand();

                cmd.CommandType = CommandType.Text;
                cmd.CommandText = @"SELECT (salt) FROM UserDB WHERE (username) = (@username);";
                cmd.Parameters.AddWithValue("@username", username);
                cmd.ExecuteNonQuery();

                using (SqlDataReader dataReader = cmd.ExecuteReader())
                {
                    while (dataReader.Read())
                    {
                        salt = Convert.FromBase64String(dataReader["salt"].ToString());
                    }
                }

                connection.Close();
            }
            catch (Exception)
            {
                MessageBox.Show("Something went wrong SALT GET EXCEPTION");
            }
            return salt;
        }

        public static byte[] GetHash(string username)
        {
            byte[] hash = { 0, 0 };

            try
            {
                connection.Open();
                SqlCommand cmd = connection.CreateCommand();

                cmd.CommandType = CommandType.Text;
                cmd.CommandText = @"SELECT (hash) FROM UserDB WHERE (username) = (@username);";
                cmd.Parameters.AddWithValue("@username", username);
                cmd.ExecuteNonQuery();

                using (SqlDataReader dataReader = cmd.ExecuteReader())
                {
                    while (dataReader.Read())
                    {
                        hash = Convert.FromBase64String(dataReader["hash"].ToString());
                    }
                }

                connection.Close();
            }
            catch (Exception)
            {
                MessageBox.Show("Something went wrong HASH GET EXCEPTION");
            }
            return hash;
        }


        public static void UpdateSaltAndHash(string username, byte[] salt, byte[] hash) //// FIX THIS AND UPDATE, + UPDATE HASH
        {
            string decodedSalt = Convert.ToBase64String(salt);
            string decodedHash = Convert.ToBase64String(hash);

            try
            {
                SqlCommand cmd = new SqlCommand();

                connection.Open();
                cmd.Connection = connection;

                cmd.CommandText = @"UPDATE UserDB SET salt = @salt, hash = @hash WHERE username = @username;";
                cmd.Parameters.AddWithValue("@username", username);
                cmd.Parameters.AddWithValue("@salt", decodedSalt);
                cmd.Parameters.AddWithValue("@hash", decodedHash);

                SqlDataReader reader = cmd.ExecuteReader();
                connection.Close();
            }
            catch (Exception)
            {
                MessageBox.Show("Something went wrong UPDATE");
            }
        }
    }
}
