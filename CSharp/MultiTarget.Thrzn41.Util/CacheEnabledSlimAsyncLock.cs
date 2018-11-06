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
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Thrzn41.Util
{

    /// <summary>
    /// Slim async lock that is allowing multiple tasks for shared resouces.
    /// </summary>
    public sealed class CacheEnabledSlimAsyncLock : SlimAsyncLock
    {

        /// <summary>
        /// Cached task for <see cref="SlimAsyncLock.LockedAsyncBlock"/>.
        /// </summary>
        private readonly Task<LockedAsyncBlock> cachedLockedBlockTask;



        /// <summary>
        /// Creates cache enabled Slim async lock.
        /// </summary>
        public CacheEnabledSlimAsyncLock()
        {
            this.cachedLockedBlockTask = Task.FromResult(new LockedAsyncBlock(this.semaphore));
        }


        /// <summary>
        /// Enter the async locked block.
        /// <see cref="LockedBlock"/> is used to exit the locked block.
        /// </summary>
        /// <param name="cancellationToken"><see cref="CancellationToken"/> to cancel.</param>
        /// <returns><see cref="LockedBlock"/>  to be used in using statement.</returns>
        public override Task<LockedAsyncBlock> EnterLockedAsyncBlockAsync(CancellationToken? cancellationToken = null)
        {
            Task waitTask;

            if (cancellationToken.HasValue)
            {
                waitTask = this.semaphore.WaitAsync(cancellationToken.Value);
            }
            else
            {
                waitTask = this.semaphore.WaitAsync();
            }
            
            if(waitTask.IsCompleted)
            {
                if (waitTask.IsCanceled)
                {
                    cancellationToken.Value.ThrowIfCancellationRequested();
                }

                return this.cachedLockedBlockTask;
            }
            else
            {
                return waitTask.ContinueWith<LockedAsyncBlock>(
                    (task) =>
                    {
                        if (waitTask.IsCanceled)
                        {
                            cancellationToken.Value.ThrowIfCancellationRequested();
                        }

                        return this.cachedLockedBlockTask.Result;
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }

        }

    }

}
