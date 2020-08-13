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
    /// Provides features for encrypting and decrypting data by password based encryption.
    /// </summary>
    public class PBEProtectedByteArray : ProtectedByteArrayWithDataProtect<PBEDataProtect>
    {


        /// <summary>
        /// Gets the salt to encrypt or decrypt data.
        /// </summary>
        public byte[] Salt
        {
            get
            {
                return this.dataProtect.Salt;
            }
        }

        /// <summary>
        /// Gets salt in base64 format.
        /// </summary>
        public string SaltBase64
        {
            get
            {
                return this.dataProtect.SaltBase64;
            }
        }


        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/>.
        /// </summary>
        /// <param name="dataProtect"><see cref="DataProtect"/> to encrypt or decrypt data.</param>
        /// <param name="data">The source data.</param>
        /// <param name="isDataEncrypted">Indicates the source data is encrypted or not.</param>
        /// <param name="isDataProtectOwner">Indicates this instance has <see cref="DataProtect"/> onwership or not.</param>
        public PBEProtectedByteArray(PBEDataProtect dataProtect, byte[] data, bool isDataEncrypted, bool isDataProtectOwner)
            : base(dataProtect, data, isDataEncrypted, isDataProtectOwner)
        {
        }


        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from char array.
        /// </summary>
        /// <param name="data">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromData(byte[] data, byte[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, salt, iterationCount, keySize, cipherMode, paddingMode), data, false, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from char array.
        /// </summary>
        /// <param name="data">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromData(byte[] data, char[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, salt, iterationCount, keySize, cipherMode, paddingMode), data, false, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from char array.
        /// </summary>
        /// <param name="data">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromData(byte[] data, string password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, salt, iterationCount, keySize, cipherMode, paddingMode), data, false, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from char array.
        /// </summary>
        /// <param name="data">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt lenght to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromData(byte[] data, byte[] password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, saltLenght, iterationCount, keySize, cipherMode, paddingMode), data, false, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from char array.
        /// </summary>
        /// <param name="data">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt lenght to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromData(byte[] data, char[] password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, saltLenght, iterationCount, keySize, cipherMode, paddingMode), data, false, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from char array.
        /// </summary>
        /// <param name="data">Char array to be encrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltLenght">Salt lenght to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromData(byte[] data, string password, int saltLenght = 128, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, saltLenght, iterationCount, keySize, cipherMode, paddingMode), data, false, true);
        }



        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromEncryptedData(byte[] encryptedData, byte[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, salt, iterationCount, keySize, cipherMode, paddingMode), encryptedData, true, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromEncryptedData(byte[] encryptedData, char[] password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, salt, iterationCount, keySize, cipherMode, paddingMode), encryptedData, true, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="salt">Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromEncryptedData(byte[] encryptedData, string password, byte[] salt, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, salt, iterationCount, keySize, cipherMode, paddingMode), encryptedData, true, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromEncryptedDataBase64(string encryptedDataBase64, byte[] password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, Convert.FromBase64String(saltBase64), iterationCount, keySize, cipherMode, paddingMode), Convert.FromBase64String(encryptedDataBase64), true, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromEncryptedDataBase64(string encryptedDataBase64, char[] password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, Convert.FromBase64String(saltBase64), iterationCount, keySize, cipherMode, paddingMode), Convert.FromBase64String(encryptedDataBase64), true, true);
        }

        /// <summary>
        /// Creates <see cref="PBEProtectedByteArray"/> from base64 encrypted data.
        /// </summary>
        /// <param name="encryptedDataBase64">Base64 encrypted data to be decrypted.</param>
        /// <param name="password">Password to generate key to encrypt and decrypt.</param>
        /// <param name="saltBase64">Base64 Salt to generate key.</param>
        /// <param name="iterationCount">Iteration count to generate key.</param>
        /// <param name="keySize">Key size in bit.</param>
        /// <param name="cipherMode"><see cref="CipherMode"/>.</param>
        /// <param name="paddingMode"><see cref="PaddingMode"/>.</param>
        /// <returns><see cref="PBEProtectedByteArray"/> instance.</returns>
        public static PBEProtectedByteArray FromEncryptedDataBase64(string encryptedDataBase64, string password, string saltBase64, int iterationCount = 4096, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return new PBEProtectedByteArray(PBEDataProtect.Create(password, Convert.FromBase64String(saltBase64), iterationCount, keySize, cipherMode, paddingMode), Convert.FromBase64String(encryptedDataBase64), true, true);
        }

    }
}
