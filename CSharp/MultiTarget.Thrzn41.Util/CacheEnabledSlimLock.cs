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

namespace Thrzn41.Util
{


    /// <summary>
    /// Slim lock that is allowing multiple threads for reading or exclusive writing.
    /// </summary>
    public sealed class CacheEnabledSlimLock : SlimLock
    {

        /// <summary>
        /// Cached <see cref="SlimLock.LockedReadBlock"/>.
        /// </summary>
        private readonly LockedReadBlock cachedLRB;

        /// <summary>
        /// Cached <see cref="SlimLock.LockedWriteBlock"/>.
        /// </summary>
        private readonly LockedWriteBlock cachedLWB;

        /// <summary>
        /// Cached <see cref="SlimLock.LockedUpgradeableReadBlock"/>.
        /// </summary>
        private readonly LockedUpgradeableReadBlock cachedLURB;



        
        /// <summary>
        /// Creates cache enabled Slim lock.
        /// </summary>
        public CacheEnabledSlimLock()
        {
            this.cachedLRB  = new LockedReadBlock(this.rwLock);
            this.cachedLWB  = new LockedWriteBlock(this.rwLock);
            this.cachedLURB = new LockedUpgradeableReadBlock(this.rwLock);
        }

        /// <summary>
        /// Creates cache enabled Slim lock with policy.
        /// </summary>
        /// <param name="policy"><see cref="LockRecursionPolicy"/> that specifies whether a lock can be entered multiple times by the same thread.</param>
        public CacheEnabledSlimLock(LockRecursionPolicy policy)
            : base(policy)
        {
            this.cachedLRB  = new LockedReadBlock(this.rwLock);
            this.cachedLWB  = new LockedWriteBlock(this.rwLock);
            this.cachedLURB = new LockedUpgradeableReadBlock(this.rwLock);
        }


        /// <summary>
        /// Enter the locked block in read mode.
        /// <see cref="LockedBlock"/> is used to exit the locked block.
        /// </summary>
        /// <returns><see cref="SlimLock.LockedReadBlock"/> to be used in using statement.</returns>
        public override LockedReadBlock EnterLockedReadBlock()
        {
            this.rwLock.EnterReadLock();

            return this.cachedLRB;
        }

        /// <summary>
        /// Enter the locked block in write mode.
        /// <see cref="LockedBlock"/> is used to exit the locked block.
        /// </summary>
        /// <returns><see cref="SlimLock.LockedWriteBlock"/> to be used in using statement.</returns>
        public override LockedWriteBlock EnterLockedWriteBlock()
        {
            this.rwLock.EnterWriteLock();

            return this.cachedLWB;
        }

        /// <summary>
        /// Enter the locked block in read mode.
        /// <see cref="LockedBlock"/> is used to exit the locked block.
        /// </summary>
        /// <returns><see cref="SlimLock.LockedUpgradeableReadBlock"/> to be used in using statement.</returns>
        public override LockedUpgradeableReadBlock EnterLockedUpgradeableReadBlock()
        {
            this.rwLock.EnterUpgradeableReadLock();

            return this.cachedLURB;
        }


    }

}
