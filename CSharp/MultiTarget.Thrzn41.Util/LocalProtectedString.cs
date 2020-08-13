/* 
 * MIT License
 * 
 * Copyright(c) 2017 thrzn41
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
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Thrzn41.Util
{

    /// <summary>
    /// Provides features for encrypting and decrypting String in local environment.
    /// This class can be used to save/load encrypted string to/from config file or database, etc.
    /// An encrypted string by this class does not have portability and can be decrypted by local user or local machine based on <see cref="DataProtectionScope"/>.
    /// Please note that this class does not provide in-memory protection.
    /// </summary>
    /// <remarks>
    /// This class does not provide in-memory protection and can be used to save/load encrypted string to/from config file or database, etc.
    /// </remarks>
    public class LocalProtectedString : ProtectedString
    {

        /// <summary>
        /// Internal encoding of this class.
        /// </summary>
        internal static readonly Encoding ENCODING = UTF8Utils.UTF8_WITHOUT_BOM;


        /// <summary>
        /// <see cref="LocalProtectedByteArray"/> to encrypt or decrypt.
        /// </summary>
        private LocalProtectedByteArray localProtectedByteArray;

        /// <summary>
        /// Indicates disposed.
        /// </summary>
        private bool disposedValue;


        /// <summary>
        /// <see cref="DataProtectionScope"/> for encrypted data.
        /// </summary>
        public DataProtectionScope ProtectionScope 
        {
            get
            {
                return this.localProtectedByteArray.ProtectionScope;
            }
        }


        /// <summary>
        /// Gets entropy to encrypt or decrypt data.
        /// </summary>
        public byte[] Entropy
        {
            get
            {
                return this.localProtectedByteArray.Entropy;
            }
        }


        /// <summary>
        /// Gets entropy in base64 format.
        /// </summary>
        public string EntropyBase64
        {
            get
            {
                if(this.Entropy == null)
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
        /// pvivate Constuctor.
        /// </summary>
        /// <param name="localProtectedByteArray"><see cref="LocalProtectedByteArray"/> for encryption and decryption.</param>
        internal LocalProtectedString(LocalProtectedByteArray localProtectedByteArray)
        {
            this.localProtectedByteArray = localProtectedByteArray;

            this.EncryptedData = this.localProtectedByteArray.EncryptedData;
        }


        /// <summary>
        /// Creates instance from char array.
        /// </summary>
        /// <param name="chars">Char array to be encrypted.</param>
        /// <param name="entropy">Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromChars(char[] chars, byte[] entropy, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedString(LocalProtectedByteArray.FromData(ENCODING.GetBytes(chars), entropy, scope));
        }

        /// <summary>
        /// Creates instance from char array.
        /// </summary>
        /// <param name="chars">Char array to be encrypted.</param>
        /// <param name="entropyBase64">Base64 Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromChars(char[] chars, string entropyBase64, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedString(LocalProtectedByteArray.FromData(ENCODING.GetBytes(chars), entropyBase64, scope));
        }

        /// <summary>
        /// Creates instance from char array.
        /// </summary>
        /// <param name="chars">Char array to be encrypted.</param>
        /// <param name="entropyLength">Entropy length to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromChars(char[] chars, int entropyLength = 128, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedString(LocalProtectedByteArray.FromData(ENCODING.GetBytes(chars), entropyLength, scope));
        }


        /// <summary>
        /// Creates instance from string.
        /// </summary>
        /// <param name="str">string to be encrypted.</param>
        /// <param name="entropy">Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromString(string str, byte[] entropy, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            var chars = str.ToCharArray();

            var ps = FromChars(chars, entropy, scope);

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
        /// <param name="entropyBase64">Base64 Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromString(string str, string entropyBase64, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return FromString(str, ((entropyBase64 != null) ? Convert.FromBase64String(entropyBase64) : null), scope);
        }

        /// <summary>
        /// Creates instance from string.
        /// </summary>
        /// <param name="str">string to be encrypted.</param>
        /// <param name="entropyLength">Entropy length to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromString(string str, int entropyLength = 128, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return FromString(str, ((entropyLength > 0) ? ProtectedDataUtils.RAND.NextBytes(entropyLength) : null), scope);
        }


        /// <summary>
        /// Creates instance from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="entropy">Entropy to be used on decryption.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromEncryptedData(byte[] encryptedData, byte[] entropy, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedString(LocalProtectedByteArray.FromEncryptedData(encryptedData, entropy, scope));
        }

        /// <summary>
        /// Creates instance from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="entropyBase64">Base64 entropy to be used on decryption.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromEncryptedDataBase64(string encryptedDataBase64, string entropyBase64, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedString(LocalProtectedByteArray.FromEncryptedDataBase64(encryptedDataBase64, entropyBase64, scope));
        }




        /// <summary>
        /// Decrypts to char array.
        /// </summary>
        /// <returns>Decrypted char array.</returns>
        public override char[] DecryptToChars()
        {
            return ENCODING.GetChars(this.localProtectedByteArray.Decrypt());
        }

        /// <summary>
        /// Decrypts the data.
        /// </summary>
        /// <returns>The decrypted data.</returns>
        public override byte[] Decrypt()
        {
            return this.localProtectedByteArray.Decrypt();
        }



        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">disposing.</param>
        protected override void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)

                    this.localProtectedByteArray?.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~LocalProtectedString()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        /// <summary>
        /// Dispose.
        /// </summary>
        public override void Dispose()
        {
            base.Dispose();

            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

    }

}
