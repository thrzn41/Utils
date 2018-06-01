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
    /// Provides feature for Hash string.
    /// </summary>
    public class HashString : IDisposable
    {

        /// <summary>
        /// Internal encoding.
        /// </summary>
        private static readonly Encoding ENCODING = UTF8Utils.UTF8_WITHOUT_BOM;


        /// <summary>
        /// Hash algorithm to be used.
        /// </summary>
        private HashAlgorithm hashAlgorithm;


        /// <summary>
        /// Constuctor of <see cref="HashString"/>.
        /// </summary>
        /// <param name="hashAlgorithm"><see cref="HashAlgorithm"/> of <see cref="HashString"/></param>
        private HashString(HashAlgorithm hashAlgorithm)
        {
            this.hashAlgorithm = hashAlgorithm;
        }


        /// <summary>
        /// Converts hash bytes to string.
        /// </summary>
        /// <param name="hash">Hash bytes.</param>
        /// <returns>Converted string.</returns>
        private string convertToString(byte[] hash)
        {
            var hashString = new StringBuilder(hash.Length << 1);

            foreach (var item in hash)
            {
                hashString.Append(item.ToString("x2"));
            }

            return hashString.ToString();
        }


        /// <summary>
        /// Computes hash string.
        /// </summary>
        /// <param name="data">Data to be computed.</param>
        /// <returns>Computed hash string.</returns>
        public string ComputeString(byte[] data)
        {
            return convertToString( this.hashAlgorithm.ComputeHash(data) );
        }

        /// <summary>
        /// Computes hash string.
        /// </summary>
        /// <param name="stream"><see cref="Stream"/> to be computed.</param>
        /// <returns>Computed hash string.</returns>
        public string ComputeString(Stream stream)
        {
            return convertToString( this.hashAlgorithm.ComputeHash(stream) );
        }




        /// <summary>
        /// Create <see cref="HMACSHA512"/> based <see cref="HashString"/>.
        /// </summary>
        /// <param name="secret">Secret bytes.</param>
        /// <returns><see cref="HMACSHA512"/> based <see cref="HashString"/></returns>
        public static HashString CreateHMACSHA512(byte[] secret)
        {
            return (new HashString( new HMACSHA512(secret) ));
        }

        /// <summary>
        /// Create <see cref="HMACSHA512"/> based <see cref="HashString"/>.
        /// </summary>
        /// <param name="secret">Secret string.</param>
        /// <returns><see cref="HMACSHA512"/> based <see cref="HashString"/></returns>
        public static HashString CreateHMACSHA512(string secret)
        {
            return CreateHMACSHA512(ENCODING.GetBytes(secret));
        }


        /// <summary>
        /// Create <see cref="HMACSHA256"/> based <see cref="HashString"/>.
        /// </summary>
        /// <param name="secret">Secret bytes.</param>
        /// <returns><see cref="HMACSHA256"/> based <see cref="HashString"/></returns>
        public static HashString CreateHMACSHA256(byte[] secret)
        {
            return (new HashString( new HMACSHA256(secret) ));
        }

        /// <summary>
        /// Create <see cref="HMACSHA256"/> based <see cref="HashString"/>.
        /// </summary>
        /// <param name="secret">Secret string.</param>
        /// <returns><see cref="HMACSHA256"/> based <see cref="HashString"/></returns>
        public static HashString CreateHMACSHA256(string secret)
        {
            return CreateHMACSHA256(ENCODING.GetBytes(secret));
        }


        /// <summary>
        /// Create <see cref="HMACSHA1"/> based <see cref="HashString"/>.
        /// </summary>
        /// <param name="secret">Secret bytes.</param>
        /// <returns><see cref="HMACSHA1"/> based <see cref="HashString"/></returns>
        public static HashString CreateHMACSHA1(byte[] secret)
        {
            return (new HashString( new HMACSHA1(secret) ));
        }

        /// <summary>
        /// Create <see cref="HMACSHA1"/> based <see cref="HashString"/>.
        /// </summary>
        /// <param name="secret">Secret string.</param>
        /// <returns><see cref="HMACSHA1"/> based <see cref="HashString"/></returns>
        public static HashString CreateHMACSHA1(string secret)
        {
            return CreateHMACSHA1(ENCODING.GetBytes(secret));
        }




#if !(DOTNETSTANDARD1_3 || DOTNETCORE1_0)

        /// <summary>
        /// Create <see cref="SHA512"/> based <see cref="HashString"/>.
        /// </summary>
        /// <returns><see cref="SHA512"/> based <see cref="HashString"/></returns>
        public static HashString CreateSHA512()
        {
            return ( new HashString(new SHA512CryptoServiceProvider()) );
        }


        /// <summary>
        /// Create <see cref="SHA256"/> based <see cref="HashString"/>.
        /// </summary>
        /// <returns><see cref="SHA256"/> based <see cref="HashString"/></returns>
        public static HashString CreateSHA256()
        {
            return ( new HashString(new SHA256CryptoServiceProvider()) );
        }


        /// <summary>
        /// Create <see cref="SHA1"/> based <see cref="HashString"/>.
        /// </summary>
        /// <returns><see cref="SHA1"/> based <see cref="HashString"/></returns>
        public static HashString CreateSHA1()
        {
            return (new HashString(new SHA1CryptoServiceProvider()));
        }


#endif




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
                    // Dispose resouce.
                    using (this.hashAlgorithm)
                    {

                    }
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~HashString() {
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
