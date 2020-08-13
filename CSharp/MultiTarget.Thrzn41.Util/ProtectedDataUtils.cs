using System;
using System.Collections.Generic;
using System.Text;

namespace Thrzn41.Util
{
    public static class ProtectedDataUtils
    {

        /// <summary>
        /// Crypto random generator.
        /// </summary>
        public static readonly CryptoRandom RAND = new CryptoRandom();


        /// <summary>
        /// Clears array.
        /// </summary>
        /// <typeparam name="T">Type in array to be cleared.</typeparam>
        /// <param name="data">Data to be cleared.</param>
        /// <returns>Value that is set in cleared array.</returns>
        public static T ClearArray<T>(T[] data)
            where T : struct
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
