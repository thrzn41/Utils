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
using System.Text;

namespace Thrzn41.Util
{

    /// <summary>
    /// Provides features for encrypting and decrypting byte array.
    /// </summary>
    public abstract class ProtectedByteArray : IDisposable
    {
        /// <summary>
        /// Indicates disposed.
        /// </summary>
        private bool disposedValue;


        /// <summary>
        /// Gets encrypted data.
        /// </summary>
        public byte[] EncryptedData { get; protected set; }

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
        /// Decrypts the data.
        /// </summary>
        /// <returns>The decrypted data.</returns>
        public abstract byte[] Decrypt();


        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">Disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)

                    ProtectedDataUtils.ClearBytes(this.EncryptedData);
                    this.EncryptedData = null;
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~ProtectedByteArray()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }


        /// <summary>
        /// Dispose.
        /// </summary>
        public virtual void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Provides features for encrypting and decrypting byte array.
    /// </summary>
    public abstract class ProtectedByteArrayWithDataProtect<T> : ProtectedByteArray
        where T : DataProtect
    {

        /// <summary>
        /// <see cref="DataProtect"/> for encryption and decryption.
        /// </summary>
        protected T dataProtect;

        /// <summary>
        /// Indicates this instance has <see cref="dataProtect"/> ownership.
        /// </summary>
        private bool isDataProtectOwner;

        /// <summary>
        /// Indicates the object disposed.
        /// </summary>
        private bool disposedValue;


        /// <summary>
        /// Creates <see cref="ProtectedByteArrayWithDataProtect{T}"/>.
        /// </summary>
        /// <param name="dataProtect"><see cref="DataProtect"/> to encrypt or decrypt data.</param>
        /// <param name="data">The source data.</param>
        /// <param name="isDataEncrypted">Indicates the source data is encrypted or not.</param>
        /// <param name="isDataProtectOwner">Indicates this instance has <see cref="DataProtect"/> onwership or not.</param>
        protected ProtectedByteArrayWithDataProtect(T dataProtect, byte[] data, bool isDataEncrypted, bool isDataProtectOwner)
        {
            this.dataProtect = dataProtect;

            if(isDataEncrypted)
            {
                this.EncryptedData = data;
            }
            else
            {
                this.EncryptedData = this.dataProtect.Encrypt(data);
            }

            this.isDataProtectOwner = isDataProtectOwner;
        }

        /// <summary>
        /// Decrypts the data.
        /// </summary>
        /// <returns>The decrypted data.</returns>
        public override byte[] Decrypt()
        {
            return this.dataProtect.Decrypt(this.EncryptedData);
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
                    if(isDataProtectOwner)
                    {
                        this.dataProtect?.Dispose();
                    }
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~ProtectedByteArray()
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
