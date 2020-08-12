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
    /// Utils for TimeZone.
    /// </summary>
    public static class DateTimeUtils
    {

        /// <summary>
        /// Normalize option.
        /// </summary>
        public enum NormalizeOption
        {
            /// <summary>
            /// Normalize datetime to a future date.
            /// </summary>
            Future,

            /// <summary>
            /// Normalize datetime to a future date.
            /// </summary>
            Past,
        }


        /// <summary>
        /// Normalizes datetime.
        /// </summary>
        /// <param name="dateTime"><see cref="DateTime"/>.</param>
        /// <param name="baseSpan"><see cref="TimeSpan"/> for normalization base.It will be better to use multiples or divisors of 60 secs, 60 mins.</param>
        /// <param name="minDiff">The minimal difference between source datetime and normalized datetime.</param>
        /// <param name="option"><see cref="NormalizeOption.Future"/> for nomalized future date.<see cref="NormalizeOption.Past"/> for normalized past date.</param>
        /// <returns>Normalized <see cref="DateTime"/>.</returns>
        public static DateTime Normalize(DateTime dateTime, TimeSpan baseSpan, TimeSpan minDiff, NormalizeOption option = NormalizeOption.Future)
        {
            long baseSpanTicks = baseSpan.Ticks;
            long minDiffTicks  = minDiff.Ticks;

            if (baseSpanTicks <= 0)
            {
                throw new ArgumentOutOfRangeException("baseSpan", ResourceMessage.ErrorMessages.BaseSpanLessThanOrEqualsZero);
            }

            if (minDiffTicks < 0)
            {
                throw new ArgumentOutOfRangeException("minDiff", ResourceMessage.ErrorMessages.MinDiffLessThanZero);
            }

            long ticks     = dateTime.Ticks;
            long direction = 1L;
            long addition  = baseSpanTicks;

            if (option == NormalizeOption.Past)
            {
                if (DateTime.MinValue.Ticks + minDiffTicks > ticks)
                {
                    throw new ArgumentOutOfRangeException("minDiff", ResourceMessage.ErrorMessages.MinDiffTooLarge);
                }

                direction = -1L;
                addition  = 0L;
            }
            else
            {
                if (DateTime.MaxValue.Ticks - minDiffTicks < ticks)
                {
                    throw new ArgumentOutOfRangeException("minDiff", ResourceMessage.ErrorMessages.MinDiffTooLarge);
                }
            }

            ticks = (((ticks + (minDiffTicks * direction)) / baseSpanTicks) * baseSpanTicks);

            if(DateTime.MaxValue.Ticks - addition < ticks)
            {
                throw new ArgumentOutOfRangeException("minDiff", ResourceMessage.ErrorMessages.MinDiffTooLarge);
            }

            return new DateTime((ticks + addition), dateTime.Kind);
        }

        /// <summary>
        /// Normalizes datetime.
        /// </summary>
        /// <param name="dateTime"><see cref="DateTime"/>.</param>
        /// <param name="baseSpan"><see cref="TimeSpan"/> for normalization base.It will be better to use multiples or divisors of 60 secs, 60 mins.</param>
        /// <param name="option"><see cref="NormalizeOption.Future"/> for nomalized future date.<see cref="NormalizeOption.Past"/> for normalized past date.</param>
        /// <returns>Normalized <see cref="DateTime"/>.</returns>
        public static DateTime Normalize(DateTime dateTime, TimeSpan baseSpan, NormalizeOption option = NormalizeOption.Future)
        {
            return Normalize(dateTime, baseSpan, TimeSpan.Zero, option);
        }

    }
}
