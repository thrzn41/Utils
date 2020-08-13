/* 
 * MIT License
 * 
 * Copyright(c) 2020 thrzn41
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Thrzn41.Util
{
    /// <summary>
    /// Provides features for encrypting and decrypting data by password based encryption.
    /// </summary>
    public class PBEDataProtect : DataProtect
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
        /// Gets the salt to encrypt or decrypt data.
        /// </summary>
        public byte[] Salt { get; private set; }

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
        /// Indicates disposed.
        /// </summary>
        private bool disposedValue;


        /// <summary>
        /// private constructor.
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/> for encryption and decryption.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/> for encryption and decryption.</param>
        private PBEDataProtect(int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
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
                this.iv  = rdb.GetBytes(blockSize >> 3);
            }
        }


        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(byte[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            var dp = new PBEDataProtect(keySize, cipherMode, paddingMode);

            dp.Salt = salt;

            dp.generateKey(password, iterationCount, BLOCK_SIZE);

            return dp;
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(char[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(ENCODING.GetBytes(password), salt, iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(string password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(ENCODING.GetBytes(password), salt, iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 encoded Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(byte[] password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(password, Convert.FromBase64String(saltBase64), iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 encoded Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(char[] password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(ENCODING.GetBytes(password), Convert.FromBase64String(saltBase64), iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 encoded Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(string password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(ENCODING.GetBytes(password), Convert.FromBase64String(saltBase64), iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLength">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(byte[] password, int saltLength = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(password, ProtectedDataUtils.RAND.NextBytes(saltLength), iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLength">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(char[] password, int saltLength = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(ENCODING.GetBytes(password), ProtectedDataUtils.RAND.NextBytes(saltLength), iterationCount, keySize, cipherMode, paddingMode);
        }

        /// <summary>
        /// Creates <see cref="PBEDataProtect"/>.
        /// </summary>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLength">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEDataProtect"/> instance.</returns>
        public static PBEDataProtect Create(string password, int saltLength = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Create(ENCODING.GetBytes(password), ProtectedDataUtils.RAND.NextBytes(saltLength), iterationCount, keySize, cipherMode, paddingMode);
        }


        /// <summary>
        /// Creates <see cref="Aes"/>.
        /// </summary>
        /// <returns><see cref="Aes"/>.</returns>
        private Aes createAes()
        {
            var aes = Aes.Create();

            aes.KeySize   = this.keySize;
            aes.BlockSize = BLOCK_SIZE;

            aes.Mode    = this.cipherMode;
            aes.Padding = this.paddingMode;

            aes.Key = this.key;
            aes.IV  = this.iv;

            return aes;
        }

        /// <summary>
        /// Checks if disposed.
        /// </summary>
        private void checkDisposed()
        {
            if (disposedValue)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
        }

        /// <summary>
        /// Encrypts the supplied data.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        public override byte[] Encrypt(byte[] data)
        {
            checkDisposed();

            using (var aes    = createAes())
            using (var memory = new MemoryStream())
            {
                using (var encryptor = aes.CreateEncryptor())
                using (var stream    = new CryptoStream(memory, encryptor, CryptoStreamMode.Write))
                {
                    stream.Write(data, 0, data.Length);
                }
                
                return memory.ToArray();
            }
        }

        /// <summary>
        /// Decrypts the supplied data.
        /// </summary>
        /// <param name="encryptedData">The encrypted data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        public override byte[] Decrypt(byte[] encryptedData)
        {
            checkDisposed();

            using (var aes    = createAes())
            using (var memory = new MemoryStream())
            {
                using (var decryptor = aes.CreateDecryptor())
                using (var encrypted = new MemoryStream(encryptedData))
                using (var stream    = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read))
                {
                    stream.CopyTo(memory);
                }

                return memory.ToArray();
            }
        }


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
                    // TODO: dispose managed state (managed objects)

                    ProtectedDataUtils.ClearBytes(this.iv);
                    ProtectedDataUtils.ClearBytes(this.key);
                    ProtectedDataUtils.ClearBytes(this.Salt);

                    this.iv   = null;
                    this.key  = null;
                    this.Salt = null;
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~PBEDataProtect()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }


        /// <summary>
        /// Dispose.
        /// </summary>
        public override void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

    }
}
