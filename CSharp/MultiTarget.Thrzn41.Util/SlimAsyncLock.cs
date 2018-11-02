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
    public class SlimAsyncLock : IDisposable
    {


        /// <summary>
        /// Locked code block.
        /// </summary>
        public sealed class LockedAsyncBlock : Thrzn41.Util.LockedBlock
        {
            /// <summary>
            /// Semaphore to lock a task.
            /// </summary>
            private readonly SemaphoreSlim semaphore;

            /// <summary>
            /// Constructor.
            /// </summary>
            /// <param name="semaphore"><see cref="SemaphoreSlim"/> to lock.</param>
            internal LockedAsyncBlock(SemaphoreSlim semaphore)
            {
                this.semaphore = semaphore;
            }

            /// <summary>
            /// Exits from the locked block.
            /// </summary>
            protected override void Exit()
            {
                this.semaphore.Release();
            }
        }




        /// <summary>
        /// Semaphore to lock a task.
        /// </summary>
        protected readonly SemaphoreSlim semaphore;


        /// <summary>
        /// Creates Slim async lock.
        /// </summary>
        public SlimAsyncLock()
        {
            this.semaphore = new SemaphoreSlim(1, 1);
        }


        /// <summary>
        /// Enter the async locked block.
        /// <see cref="LockedBlock"/> is used to exit the locked block.
        /// </summary>
        /// <param name="cancellationToken"><see cref="CancellationToken"/> to cancel.</param>
        /// <returns><see cref="LockedBlock"/>  to be used in using statement.</returns>
        public async Task<LockedAsyncBlock> EnterLockedAsyncBlockAsync(CancellationToken? cancellationToken = null)
        {
            if(cancellationToken.HasValue)
            {
                await this.semaphore.WaitAsync(cancellationToken.Value);
            }
            else
            {
                await this.semaphore.WaitAsync();
            }

            // For a higher performance, the cached Task<LockedAsyncBlock> can be used.
            // However, a new instance is created for each requests in current design,
            // bacause each LockedBlocks should be independent.
            // If you want higher performance, you can override this method, then cache and return the cached Task<LockedAsyncBlock>.
            return new LockedAsyncBlock(this.semaphore);
        }


        /// <summary>
        /// Executes in lock.
        /// </summary>
        /// <param name="func">This function is executed in reader lock.</param>
        /// <returns><see cref="Task"/> of the async operation.</returns>
        public async Task ExecuteInLockAsync(Func<Task> func)
        {
            using (await EnterLockedAsyncBlockAsync())
            {
                await func();
            }
        }

        /// <summary>
        /// Executes in lock.
        /// </summary>
        /// <typeparam name="TResult">Type of result.</typeparam>
        /// <param name="func">Function that returns value.This function is executed in reader lock.</param>
        /// <returns><see cref="Task{TResult}"/> of the async operation.</returns>
        public async Task<TResult> ExecuteInLockAsync<TResult>(Func< Task<TResult> > func)
        {
            using (await EnterLockedAsyncBlockAsync())
            {
                return (await func());
            }
        }

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
                    using (this.semaphore)
                    {

                    }
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~SlimAsyncLock() {
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
