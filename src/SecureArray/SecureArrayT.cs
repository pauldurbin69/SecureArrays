﻿// Created after reading https://stackoverflow.com/questions/1166952/net-secure-memory-structures

using System;
using System.Text;

namespace SecureArrays
{

    /// <summary>
    /// Manage an array that holds sensitive information.
    /// </summary>
    /// <typeparam name="T">
    /// The type of the array. Limited to built in types.
    /// </typeparam>
    public sealed class SecureArray<T> : SecureArray
    {
        private readonly long size;

        /// <summary>
        /// Initialize a new instance of the <see cref="SecureArray{T}"/> class.
        /// </summary>
        /// <param name="size">
        /// The number of elements in the secure array.
        /// </param>
        /// <param name="noswap">
        /// Set to true to do a Win32 VirtualLock on the allocated buffer to
        /// keep it from swapping to disk.
        /// </param>
        public SecureArray(long size, bool noswap = true)
        {
            Buffer = new T[size];
            Init(Buffer, BuiltInTypeElementSize(Buffer) * size, noswap);
            this.size = size;
        }

        /// <summary>
        /// Gets the secure array.
        /// </summary>
        public T[] Buffer { get; }

        public int Length => Convert.ToInt32(size);

        public long LengthLong => size;

        /// <summary>
        /// Gets or sets elements in the secure array.
        /// </summary>
        /// <param name="i">
        /// The index of the element.
        /// </param>
        /// <returns>
        /// The element.
        /// </returns>
        public T this[int i]
        {
            get
            {
                return Buffer[i];
            }

            set
            {
                Buffer[i] = value;
            }
        }
    }
}