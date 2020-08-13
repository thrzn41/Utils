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
    public class LocalProtectedByteArray : ProtectedByteArrayWithDataProtect<LocalDataProtect>
    {

        /// <summary>
        /// <see cref="DataProtectionScope"/> for encrypted data.
        /// </summary>
        public DataProtectionScope ProtectionScope
        {
            get
            {
                return this.dataProtect.ProtectionScope;

            }
        }

        /// <summary>
        /// Gets entropy to encrypt or decrypt data.
        /// </summary>
        public byte[] Entropy
        {
            get
            {
                return this.dataProtect.Entropy;
            }
        }

        /// <summary>
        /// Gets entropy in base64 format.
        /// </summary>
        public string EntropyBase64
        {
            get
            {
                return this.dataProtect.EntropyBase64;
            }
        }


        /// <summary>
        /// Creates <see cref="LocalProtectedByteArray"/>.
        /// </summary>
        /// <param name="dataProtect"><see cref="DataProtect"/> to encrypt or decrypt data.</param>
        /// <param name="data">The source data.</param>
        /// <param name="isDataEncrypted">Indicates the source data is encrypted or not.</param>
        /// <param name="isDataProtectOwner">Indicates this instance has <see cref="DataProtect"/> onwership or not.</param>
        internal LocalProtectedByteArray(LocalDataProtect dataProtect, byte[] data, bool isDataEncrypted, bool isDataProtectOwner)
            : base(dataProtect, data, isDataEncrypted, isDataProtectOwner)
        {
        }


        /// <summary>
        /// Creates <see cref="LocalProtectedByteArray"/> from data.
        /// </summary>
        /// <param name="data">Data to be encrypted.</param>
        /// <param name="entropy">Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalProtectedByteArray"/> instance.</returns>
        public static LocalProtectedByteArray FromData(byte[] data, byte[] entropy, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedByteArray(LocalDataProtect.Create(entropy, scope), data, false, true);
        }

        /// <summary>
        /// Creates <see cref="LocalProtectedByteArray"/> from data.
        /// </summary>
        /// <param name="data">Data to be encrypted.</param>
        /// <param name="entropyBase64">Base64 Entropy to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalProtectedByteArray"/> instance.</returns>
        public static LocalProtectedByteArray FromData(byte[] data, string entropyBase64, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedByteArray(LocalDataProtect.Create(entropyBase64, scope), data, false, true);
        }

        /// <summary>
        /// Creates <see cref="LocalProtectedByteArray"/> from data.
        /// </summary>
        /// <param name="data">Char array to be encrypted.</param>
        /// <param name="entropyLength">Entropy length to be used on encrypting.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalProtectedByteArray"/> instance.</returns>
        public static LocalProtectedByteArray FromData(byte[] data, int entropyLength = 128, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedByteArray(LocalDataProtect.Create(entropyLength, scope), data, false, true);
        }


        /// <summary>
        /// Creates <see cref="LocalProtectedByteArray"/> from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="entropy">Entropy to be used on decryption.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalProtectedByteArray"/> instance.</returns>
        public static LocalProtectedByteArray FromEncryptedData(byte[] encryptedData, byte[] entropy, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedByteArray(LocalDataProtect.Create(entropy, scope), encryptedData, true, true);
        }

        /// <summary>
        /// Creates <see cref="LocalProtectedByteArray"/> from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="entropyBase64">Base64 entropy to be used on decryption.</param>
        /// <param name="scope"><see cref="DataProtectionScope"/> for encrypted data.</param>
        /// <returns><see cref="LocalProtectedByteArray"/> instance.</returns>
        public static LocalProtectedByteArray FromEncryptedDataBase64(string encryptedDataBase64, string entropyBase64, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            return new LocalProtectedByteArray(LocalDataProtect.Create(entropyBase64, scope), Convert.FromBase64String(encryptedDataBase64), true, true);
        }

    }
}
