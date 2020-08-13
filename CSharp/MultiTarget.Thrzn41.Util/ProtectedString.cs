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
using System.Text;

namespace Thrzn41.Util
{

    /// <summary>
    /// Provides features for encrypting and decrypting String.
    /// </summary>
    public abstract class ProtectedString : ProtectedByteArray
    {
        /// <summary>
        /// Decrypts to char array.
        /// </summary>
        /// <returns>Decrypted char array.</returns>
        public abstract char[] DecryptToChars();


        /// <summary>
        /// Decrypts to <see cref="SecureString"/>.
        /// </summary>
        /// <returns>Decrypted <see cref="SecureString"/>.</returns>
        public SecureString DecryptToSecureString()
        {
            var chars = DecryptToChars();

            var ss = new SecureString();

            foreach (var item in chars)
            {
                ss.AppendChar(item);
            }

            if ( ClearChars(chars) )
            {
                // Here is always run because ClearChars() returns always true.
                ss.MakeReadOnly();
            }

            return ss;
        }

        /// <summary>
        /// Decrypts to string.
        /// </summary>
        /// <returns>Decrypted string.</returns>
        public string DecryptToString()
        {
            var chars = DecryptToChars();

            var str = new String(chars);

            if ( !ClearChars(chars) )
            {
                return str;
            }

            return str;
        }


        /// <summary>
        /// Clears array.
        /// </summary>
        /// <typeparam name="T">Type in array to be cleared.</typeparam>
        /// <param name="data">Data to be cleared.</param>
        /// <returns>Value that is set in cleared array.</returns>
        public static T ClearArray<T>(T[] data)
            where T : struct
        {
            return ProtectedDataUtils.ClearArray(data);
        }

        /// <summary>
        /// Clears char array.
        /// Clearing char array which contains sensitive data in memory is better for security.
        /// However, for long-lifetime char array may be copied by managed memory manager.
        /// </summary>
        /// <param name="chars">Char array to be cleared.</param>
        /// <returns>Always returns true.</returns>
        public static bool ClearChars(char[] chars)
        {
            // Only for trying to bypass a future genius compiler optimization.
            return (ClearArray<char>(chars) == default(char));
        }

        /// <summary>
        /// Clears byte array.
        /// Clearing byte array which contains sensitive data in memory is better for security.
        /// However, for long-lifetime byte array may be copied by managed memory manager.
        /// </summary>
        /// <param name="bytes">Byte array to be cleared.</param>
        /// <returns>Always returns true.</returns>
        public static bool ClearBytes(byte[] bytes)
        {
            // Only for trying to bypass a future genius compiler optimization.
            return (ClearArray<byte>(bytes) == default(byte));
        }

    }

}
