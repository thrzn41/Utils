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
    public class LocalProtectedString : ProtectedString, IDisposable
    {

        /// <summary>
        /// Internal encoding of this class.
        /// </summary>
        private static readonly Encoding ENCODING = UTF8Utils.UTF8_WITHOUT_BOM;


        
        
        /// <summary>
        /// <see cref="DataProtectionScope"/> for encrypted data.
        /// </summary>
        public DataProtectionScope ProtectionScope { get; private set; }

        /// <summary>
        /// Gets encrypted data.
        /// </summary>
        public byte[] EncryptedData { get; private set; }

        /// <summary>
        /// Gets entropy to encrypt or decrypt data.
        /// </summary>
        public byte[] Entropy { get; private set; }

        /// <summary>
        /// Gets encrypted data in base64 format.
        /// </summary>
        public string EncryptedDataBase64
        {
            get
            {
                return Convert.ToBase64String(this.EncryptedData, Base64FormattingOptions.None);
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

                return Convert.ToBase64String(this.Entropy, Base64FormattingOptions.None);
            }
        }




        /// <summary>
        /// pvivate Constuctor.
        /// </summary>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encryption and decryption.</param>
        private LocalProtectedString(DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            this.ProtectionScope = scope;
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
            var ps = new LocalProtectedString(scope);

            if(entropyLength > 0)
            {
                ps.Entropy = RAND.NextBytes(entropyLength);
            }

            ps.EncryptedData = ProtectedData.Protect(
                                    ENCODING.GetBytes(chars),
                                    ps.Entropy,
                                    scope);

            return ps;
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
            var chars = str.ToCharArray();

            var ps    = FromChars(chars, entropyLength, scope);

            if ( !ClearChars(chars) )
            {
                // Only for trying to bypass a future genius compiler optimization.
                return ps;
            }
            
            return ps;
        }


        /// <summary>
        /// Creates instance from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="entropy">Entropy to be used on decryption.</param>
        /// <param name="scope"><see cref="StringProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromEncryptedData(byte[] encryptedData, byte[] entropy, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            var ps = new LocalProtectedString(scope);

            ps.EncryptedData = encryptedData;
            ps.Entropy       = entropy;

            return ps;
        }

        /// <summary>
        /// Creates instance from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="entropyBase64">Base64 entropy to be used on decryption.</param>
        /// <param name="scope"><see cref="StringProtectionScope"/> for encrypted data.</param>
        /// <returns>ProtectedString instance.</returns>
        public static LocalProtectedString FromEncryptedDataBase64(string encryptedDataBase64, string entropyBase64, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            byte[] encryptedData = Convert.FromBase64String(encryptedDataBase64);
            byte[] entropy       = null;

            if( !String.IsNullOrEmpty(entropyBase64) )
            {
                entropy = Convert.FromBase64String(entropyBase64);
            }

            return FromEncryptedData(encryptedData, entropy, scope);
        }




        /// <summary>
        /// Decrypts to char array.
        /// </summary>
        /// <returns>Decrypted char array.</returns>
        public override char[] DecryptToChars()
        {
            return ENCODING.GetChars(ProtectedData.Unprotect(this.EncryptedData, this.Entropy, this.ProtectionScope));
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    ClearBytes(this.Entropy);
                    ClearBytes(this.EncryptedData);
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~LocalProtectedString() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
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
