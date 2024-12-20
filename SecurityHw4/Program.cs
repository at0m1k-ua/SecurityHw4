using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace CryptoSystem
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("Choose encryption algorithm (DES/TripleDES/AES):");
            string algorithm = Console.ReadLine()?.ToUpper();

            if (algorithm != "DES" && algorithm != "TRIPLEDES" && algorithm != "AES")
            {
                Console.WriteLine("Invalid algorithm. Please choose DES, TripleDES, or AES.");
                return;
            }

            Console.WriteLine("Enter text to encrypt:");
            string plaintext = Console.ReadLine();

            byte[] key, iv;
            SymmetricAlgorithm cryptoAlgorithm = CreateAlgorithm(algorithm, out key, out iv);

            byte[] encryptedData = Encrypt(cryptoAlgorithm, plaintext, key, iv);
            Console.WriteLine("Encrypted data (Base64): " + Convert.ToBase64String(encryptedData));

            string decryptedText = Decrypt(cryptoAlgorithm, encryptedData, key, iv);
            Console.WriteLine("Decrypted text: " + decryptedText);
        }

        static SymmetricAlgorithm CreateAlgorithm(string algorithm, out byte[] key, out byte[] iv)
        {
            SymmetricAlgorithm cryptoAlgorithm;

            switch (algorithm)
            {
                case "DES":
                    cryptoAlgorithm = new DESCryptoServiceProvider();
                    break;
                case "TRIPLEDES":
                    cryptoAlgorithm = new TripleDESCryptoServiceProvider();
                    break;
                case "AES":
                    cryptoAlgorithm = new AesCryptoServiceProvider();
                    break;
                default:
                    throw new ArgumentException("Invalid algorithm");
            }

            // Check if key and IV files exist
            string keyFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{algorithm}_key.bin");
            string ivFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{algorithm}_iv.bin");

            if (File.Exists(keyFile) && File.Exists(ivFile))
            {
                key = File.ReadAllBytes(keyFile);
                iv = File.ReadAllBytes(ivFile);
            }
            else
            {
                cryptoAlgorithm.GenerateKey();
                cryptoAlgorithm.GenerateIV();
                key = cryptoAlgorithm.Key;
                iv = cryptoAlgorithm.IV;

                File.WriteAllBytes(keyFile, key);
                File.WriteAllBytes(ivFile, iv);
            }

            return cryptoAlgorithm;
        }

        static byte[] Encrypt(SymmetricAlgorithm algorithm, string plaintext, byte[] key, byte[] iv)
        {
            algorithm.Key = key;
            algorithm.IV = iv;

            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                byte[] data = Encoding.UTF8.GetBytes(plaintext);
                cs.Write(data, 0, data.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        static string Decrypt(SymmetricAlgorithm algorithm, byte[] ciphertext, byte[] key, byte[] iv)
        {
            algorithm.Key = key;
            algorithm.IV = iv;

            using (MemoryStream ms = new MemoryStream(ciphertext))
            using (CryptoStream cs = new CryptoStream(ms, algorithm.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader reader = new StreamReader(cs))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
