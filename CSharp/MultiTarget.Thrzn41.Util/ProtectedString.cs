using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace Thrzn41.Util
{
    public abstract class ProtectedString
    {

        /// <summary>
        /// Crypto random generator.
        /// </summary>
        protected static readonly CryptoRandom RAND = new CryptoRandom();




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

            if (!ClearChars(chars))
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
            where T : IComparable<T>
        {
            if (data == null || data.Length == 0)
            {
                return default(T);
            }

            // To prevent to be removed by a future genius compiler optimization,
            // gets and sets most of array item.
            // This is not perfect way.
            data[0] = default(T);

            for (int i = 1; i < data.Length; i++)
            {
                data[i] = data[i - 1];
            }

            // Only for trying to bypass a future genius compiler optimization.
            return (data[RAND.NextInt(data.Length)]);
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
        /// <param name="chars">Byte array to be cleared.</param>
        /// <returns>Always returns true.</returns>
        public static bool ClearBytes(byte[] bytes)
        {
            // Only for trying to bypass a future genius compiler optimization.
            return (ClearArray<byte>(bytes) == default(byte));
        }

    }

}
