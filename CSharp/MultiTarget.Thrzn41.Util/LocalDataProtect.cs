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
using System.Security.Cryptography;
using System.Text;

namespace Thrzn41.Util
{

    /// <summary>
    /// Provides features for encrypting and decrypting data in local environment.
    /// This class can be used to save/load encrypted string to/from config file or database, etc.
    /// An encrypted string by this class does not have portability and can be decrypted by local user or local machine based on <see cref="DataProtectionScope"/>.
    /// Please note that this class does not provide in-memory protection.
    /// </summary>
    /// <remarks>
    /// This class does not provide in-memory protection and can be used to save/load encrypted string to/from config file or database, etc.
    /// </remarks>
    public class LocalDataProtect : DataProtect
    {

        /// <summary>
        /// <see cref="DataProtectionScope"/> for encrypted data.
        /// </summary>
        public DataProtectionScope ProtectionScope { get; private set; }

        /// <summary>
        /// Gets entropy to encrypt or decrypt data.
        /// </summary>
        public byte[] Entropy { get; private set; }

        /// <summary>
        /// Gets entropy in base64 format.
        /// </summary>
        public string EntropyBase64
        {
            get
            {
                if (this.Entropy == null)
                {
                    return null;
                }

#if (DOTNETSTANDARD1_3 || DOTNETCORE1_0)
                return Convert.ToBase64String(this.Entropy);
#else
                return Convert.ToBase64String(this.Entropy, Base64FormattingOptions.None);
#endif
            }
        }

        /// <summary>
        /// Indicates disposed or not.
        /// </summary>
        private bool disposedValue;


        /// <summary>
        /// pvivate Constuctor.
        /// </summary>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encryption and decryption.</param>
        private LocalDataProtect(DataProtectionScope scope)
        {
            this.ProtectionScope = scope;
        }

        /// <summary>
        /// Creates <see cref="LocalDataProtect"/>.
        /// </summary>
        /// <param name="entropy">Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalDataProtect"/> instance.</returns>
        public static LocalDataProtect Create(byte[] entropy, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            var dp = new LocalDataProtect(scope);

            dp.Entropy = entropy;

            return dp;
        }

        /// <summary>
        /// Creates <see cref="LocalDataProtect"/>.
        /// </summary>
        /// <param name="entropyBase64">Base64 Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalDataProtect"/> instance.</returns>
        public static LocalDataProtect Create(string entropyBase64, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return Create(((entropyBase64 != null) ? Convert.FromBase64String(entropyBase64) : null), scope);
        }

        /// <summary>
        /// Creates <see cref="LocalDataProtect"/>.
        /// </summary>
        /// <param name="entropyLength">Entropy length to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalDataProtect"/> instance.</returns>
        public static LocalDataProtect Create(int entropyLength = 128, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return Create(((entropyLength > 0) ? ProtectedDataUtils.RAND.NextBytes(entropyLength) : null), scope);
        }


        /// <summary>
        /// Checks if disposed.
        /// </summary>
        private void checkDisposed()
        {
            if(disposedValue)
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

            return ProtectedData.Protect(data, this.Entropy, this.ProtectionScope);
        }

        /// <summary>
        /// Decrypts the supplied data.
        /// </summary>
        /// <param name="encryptedData">The encrypted data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        public override byte[] Decrypt(byte[] encryptedData)
        {
            checkDisposed();

            return ProtectedData.Unprotect(encryptedData, this.Entropy, this.ProtectionScope);
        }



        /// <summary>
        /// Creates <see cref="ProtectedByteArray"/> from data.
        /// </summary>
        /// <param name="data">Data to be encrypted.</param>
        /// <returns><see cref="ProtectedByteArray"/> instance.</returns>
        public ProtectedByteArray CreateProtectedByteArrayFromData(byte[] data)
        {
            return new LocalProtectedByteArray(this, data, false, false);
        }

        /// <summary>
        /// Creates <see cref="ProtectedByteArray"/> from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <returns><see cref="ProtectedByteArray"/> instance.</returns>
        public ProtectedByteArray CreateProtectedByteArrayFromEncryptedData(byte[] encryptedData)
        {
            return new LocalProtectedByteArray(this, encryptedData, true, false);
        }

        /// <summary>
        /// Creates <see cref="ProtectedByteArray"/> from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <returns><see cref="ProtectedByteArray"/> instance.</returns>
        public ProtectedByteArray CreateProtectedByteArrayFromEncryptedDataBase64(string encryptedDataBase64)
        {
            return new LocalProtectedByteArray(this, Convert.FromBase64String(encryptedDataBase64), true, false);
        }


        /// <summary>
        /// Creates <see cref="ProtectedString"/> from data.
        /// </summary>
        /// <param name="chars">Char array to be encrypted.</param>
        /// <returns><see cref="ProtectedString"/> instance.</returns>
        public ProtectedString CreateProtectedStringFromChars(char[] chars)
        {
            return new LocalProtectedString(new LocalProtectedByteArray(this, LocalProtectedString.ENCODING.GetBytes(chars), false, false));
        }

        /// <summary>
        /// Creates <see cref="ProtectedString"/> from data.
        /// </summary>
        /// <param name="str">Char array to be encrypted.</param>
        /// <returns><see cref="ProtectedString"/> instance.</returns>
        public ProtectedString CreateProtectedStringFromString(string str)
        {
            return new LocalProtectedString(new LocalProtectedByteArray(this, LocalProtectedString.ENCODING.GetBytes(str), false, false));
        }


        /// <summary>
        /// Creates <see cref="ProtectedString"/> from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <returns><see cref="ProtectedString"/> instance.</returns>
        public ProtectedString CreateProtectedStringFromEncryptedData(byte[] encryptedData)
        {
            return new LocalProtectedString(new LocalProtectedByteArray(this, encryptedData, true, false));
        }

        /// <summary>
        /// Creates <see cref="ProtectedString"/> from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <returns><see cref="ProtectedString"/> instance.</returns>
        public ProtectedString CreateProtectedStringFromEncryptedDataBase64(string encryptedDataBase64)
        {
            return new LocalProtectedString(new LocalProtectedByteArray(this, Convert.FromBase64String(encryptedDataBase64), true, false));
        }


        /// <summary>
        /// Converts to <see cref="ProtectedByteArray"/> from source ProtectedByteArray.
        /// </summary>
        /// <param name="source">Source ProtectedByteArray.</param>
        /// <returns>Converted <see cref="ProtectedByteArray"/>.</returns>
        public ProtectedByteArray ConvertToProtectedByteArray(ProtectedByteArray source)
        {
            var data = source.Decrypt();

            var result = this.CreateProtectedByteArrayFromData(data);

            ProtectedDataUtils.ClearBytes(data);

            return result;
        }

        /// <summary>
        /// Converts to <see cref="ProtectedString"/> from source ProtectedByteArray.
        /// </summary>
        /// <param name="source">Source ProtectedByteArray.</param>
        /// <returns>Converted <see cref="ProtectedString"/>.</returns>
        public ProtectedString ConvertToProtectedString(ProtectedString source)
        {
            var data = source.DecryptToChars();

            var result = this.CreateProtectedStringFromChars(data);

            ProtectedString.ClearChars(data);

            return result;
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

                    ProtectedDataUtils.ClearBytes(this.Entropy);
                    this.Entropy = null;
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~LocalDataProtect()
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
