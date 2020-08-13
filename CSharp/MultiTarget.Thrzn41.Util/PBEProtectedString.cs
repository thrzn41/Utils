/* 
 * MIT License
 * 
 * Copyright(c) 2018 thrzn41
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
    /// Provides features for encrypting and decrypting String by password based encryption.
    /// </summary>
    public class PBEProtectedString : ProtectedString
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
        /// <see cref="PBEProtectedByteArray"/> to encrypt or decrypt.
        /// </summary>
        private PBEProtectedByteArray pbeProtectedByteArray;


        /// <summary>
        /// Indicate disposed.
        /// </summary>
        private bool disposedValue;


        /// <summary>
        /// Gets the salt to encrypt or decrypt data.
        /// </summary>
        public byte[] Salt
        {
            get
            {
                return this.pbeProtectedByteArray.Salt;
            }
        }


        /// <summary>
        /// Gets salt in base64 format.
        /// </summary>
        public string SaltBase64
        {
            get
            {
                return this.pbeProtectedByteArray.SaltBase64;
            }
        }



        /// <summary>
        /// pvivate Constuctor.
        /// </summary>
        /// <param name="pbeProtectedByteArray"><see cref="PBEProtectedByteArray"/> for encryption and decryption.</param>
        internal PBEProtectedString(PBEProtectedByteArray pbeProtectedByteArray)
        {
            this.pbeProtectedByteArray = pbeProtectedByteArray;

            this.EncryptedData = this.pbeProtectedByteArray.EncryptedData;
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
            return new PBEProtectedString(PBEProtectedByteArray.FromData(ENCODING.GetBytes(chars), password, saltLenght, iterationCount, keySize, cipherMode, paddingMode));
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
            return new PBEProtectedString(PBEProtectedByteArray.FromEncryptedData(encryptedData, password, salt, iterationCount, keySize, cipherMode, paddingMode));
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
            return ENCODING.GetChars(this.pbeProtectedByteArray.Decrypt());
        }


        /// <summary>
        /// Decrypts the data.
        /// </summary>
        /// <returns>The decrypted data.</returns>
        public override byte[] Decrypt()
        {
            return this.pbeProtectedByteArray.Decrypt();
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

                    this.pbeProtectedByteArray?.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~PBEProtectedString()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }


        /// <summary>
        /// dispose.
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
