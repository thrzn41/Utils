using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Thrzn41.Util
{

    /// <summary>
    /// Provides features for encrypting and decrypting String by password based encryption.
    /// </summary>
    public class PBEProtectedString : ProtectedString, IDisposable
    {

        /// <summary>
        /// Block size.
        /// </summary>
        private const int BLOCK_SIZE = 128;


        /// <summary>
        /// Internal encoding of this class.
        /// </summary>
        private static readonly Encoding ENCODING = UTF8Utils.UTF8_WITHOUT_BOM;




        /// <summary>
        /// Gets encrypted data.
        /// </summary>
        public byte[] EncryptedData { get; private set; }

        /// <summary>
        /// Gets the salt to encrypt or decrypt data.
        /// </summary>
        public byte[] Salt { get; private set; }

        /// <summary>
        /// Gets encrypted data in base64 format.
        /// </summary>
        public string EncryptedDataBase64
        {
            get
            {
#if (DOTNETSTANDARD1_3 || DOTNETCORE1_0)
                return Convert.ToBase64String(this.EncryptedData);
#else
                return Convert.ToBase64String(this.EncryptedData, Base64FormattingOptions.None);
#endif
            }
        }

        /// <summary>
        /// Gets salt in base64 format.
        /// </summary>
        public string SaltBase64
        {
            get
            {
#if (DOTNETSTANDARD1_3 || DOTNETCORE1_0)
                return Convert.ToBase64String(this.Salt);
#else
                return Convert.ToBase64String(this.Salt, Base64FormattingOptions.None);
#endif
            }
        }


        /// <summary>
        /// Key for encryption and decryption.
        /// </summary>
        private byte[] key;

        /// <summary>
        /// Initialization vector for encryption and decryption.
        /// </summary>
        private byte[] iv;

        /// <summary>
        /// Key size.
        /// </summary>
        private int keySize;

        /// <summary>
        /// <see cref="CipherMode"/> for encryption and decryption.
        /// </summary>
        private CipherMode cipherMode;

        /// <summary>
        /// <see cref="PaddingMode"/> for encryption and decryption.
        /// </summary>
        private PaddingMode paddingMode;




        /// <summary>
        /// private constructor.
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/> for encryption and decryption.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/> for encryption and decryption.</param>
        private PBEProtectedString(int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            this.keySize     = keySize;
            this.cipherMode  = cipherMode;
            this.paddingMode = paddingMode;
        }



        /// <summary>
        /// Generates key and iv.
        /// </summary>
        /// <param name="password">Password to generate key and iv.</param>
        /// <param name="iterationCount">Iteration count to generate.</param>
        /// <param name="blockSize">Block size.</param>
        private void generateKey(byte[] password, int iterationCount, int blockSize)
        {
            using (var rdb = new Rfc2898DeriveBytes(password, this.Salt, Math.Max(iterationCount, 0)))
            {
                this.key = rdb.GetBytes(this.keySize >> 3);
                this.iv  = rdb.GetBytes(blockSize    >> 3);
            }
        }


        /// <summary>
        /// Creates instance from char array.
        /// </summary>
        /// <param name="chars">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt length to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromChars(char[] chars, byte[] password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            var ps = new PBEProtectedString(keySize, cipherMode, paddingMode);

            if (saltLenght > 0)
            {
                ps.Salt = RAND.NextBytes(saltLenght);
            }

            ps.generateKey(password, iterationCount, BLOCK_SIZE);

            using (var aes = Aes.Create())
            {
                aes.KeySize   = ps.keySize;
                aes.BlockSize = BLOCK_SIZE;

                aes.Mode    = ps.cipherMode;
                aes.Padding = ps.paddingMode;

                aes.Key = ps.key;
                aes.IV  = ps.iv;

                using (var memory = new MemoryStream())
                {
                    using (var encryptor = aes.CreateEncryptor())
                    using (var stream    = new CryptoStream(memory, encryptor, CryptoStreamMode.Write))
                    using (var writer    = new StreamWriter(stream, ENCODING))
                    {
                        writer.Write(chars);
                    }

                    ps.EncryptedData = memory.ToArray();
                }
            }

            return ps;
        }

        /// <summary>
        /// Creates instance from char array.
        /// </summary>
        /// <param name="chars">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt length to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromChars(char[] chars, char[] password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromChars(chars, ENCODING.GetBytes(password), saltLenght, iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates instance from char array.
        /// </summary>
        /// <param name="chars">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt length to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromChars(char[] chars, string password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromChars(chars, ENCODING.GetBytes(password), saltLenght, iterationCount, keySize, cipherMode, paddingMode);
        }


        /// <summary>
        /// Creates instance from string.
        /// </summary>
        /// <param name="str">string to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt length to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromString(string str, byte[] password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            var chars = str.ToCharArray();

            var ps = FromChars(chars, password, saltLenght, iterationCount, keySize, cipherMode, paddingMode);

            if (!ClearChars(chars))
            {
                // Only for trying to bypass a future genius compiler optimization.
                return ps;
            }

            return ps;
        }

        /// <summary>
        /// Creates instance from string.
        /// </summary>
        /// <param name="str">string to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt length to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromString(string str, char[] password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromString(str, ENCODING.GetBytes(password), saltLenght, iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates instance from string.
        /// </summary>
        /// <param name="str">string to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt length to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromString(string str, string password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromString(str, ENCODING.GetBytes(password), saltLenght, iterationCount, keySize, cipherMode, paddingMode);
        }


        /// <summary>
        /// Creates instance from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromEncryptedData(byte[] encryptedData, byte[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            var ps = new PBEProtectedString(keySize, cipherMode, paddingMode);

            ps.EncryptedData = encryptedData;
            ps.Salt          = salt;

            ps.generateKey(password, iterationCount, BLOCK_SIZE);

            return ps;
        }

        /// <summary>
        /// Creates instance from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromEncryptedData(byte[] encryptedData, char[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromEncryptedData(encryptedData, ENCODING.GetBytes(password), salt, iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates instance from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromEncryptedData(byte[] encryptedData, string password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromEncryptedData(encryptedData, ENCODING.GetBytes(password), salt, iterationCount, keySize, cipherMode, paddingMode);
        }


        /// <summary>
        /// Creates instance from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromEncryptedDataBase64(string encryptedDataBase64, byte[] password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromEncryptedData(
                Convert.FromBase64String(encryptedDataBase64),
                password,
                Convert.FromBase64String(saltBase64),
                iterationCount,
                keySize, cipherMode,
                paddingMode);
        }

        /// <summary>
        /// Creates instance from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromEncryptedDataBase64(string encryptedDataBase64, char[] password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromEncryptedDataBase64(encryptedDataBase64, ENCODING.GetBytes(password), saltBase64, iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates instance from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns>PBEProtectedString instance.</returns>
        public static PBEProtectedString FromEncryptedDataBase64(string encryptedDataBase64, string password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return FromEncryptedDataBase64(encryptedDataBase64, ENCODING.GetBytes(password), saltBase64, iterationCount, keySize, cipherMode, paddingMode);
        }


        /// <summary>
        /// Decrypts to char array.
        /// </summary>
        /// <returns>Decrypted char array.</returns>
        public override char[] DecryptToChars()
        {
            char[] result;

            using (var aes = Aes.Create())
            {
                aes.KeySize   = this.keySize;
                aes.BlockSize = BLOCK_SIZE;

                aes.Mode    = this.cipherMode;
                aes.Padding = this.paddingMode;

                aes.Key = this.key;
                aes.IV  = this.iv;

                using (var memory = new MemoryStream())
                {
                    using (var decryptor = aes.CreateDecryptor())
                    using (var encrypted = new MemoryStream(this.EncryptedData))
                    using (var stream    = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read))
                    {
                        stream.CopyTo(memory);
                    }

                    result = ENCODING.GetChars(memory.ToArray());
                }

                return result;
            }

        }

#region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls


        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    ClearBytes(this.iv);
                    ClearBytes(this.key);
                    ClearBytes(this.Salt);
                    ClearBytes(this.EncryptedData);
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~PBEProtectedString() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        /// <summary>
        /// Dispose.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
#endregion

    }

}
