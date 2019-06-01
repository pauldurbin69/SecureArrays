// Created after reading https://stackoverflow.com/questions/1166952/net-secure-memory-structures

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace SecureArrays
{
    /// <summary>
    /// Base class of all <see cref="SecureArray{T}"/> classes.
    /// </summary>
    public class SecureArray : IDisposable
    {
        /// <summary>
        /// Cannot find a way to do a compile-time verification that the
        /// array element type is one of these so this dictionary gets
        /// used to do it at runtime.
        /// </summary>
        private static readonly Dictionary<Type, int> TypeSizes =
            new Dictionary<Type, int>
                {
                { typeof(sbyte), sizeof(sbyte) },
                { typeof(byte), sizeof(byte) },
                { typeof(short), sizeof(short) },
                { typeof(ushort), sizeof(ushort) },
                { typeof(int), sizeof(int) },
                { typeof(uint), sizeof(uint) },
                { typeof(long), sizeof(long) },
                { typeof(ulong), sizeof(ulong) },
                { typeof(char), sizeof(char) },
                { typeof(float), sizeof(float) },
                { typeof(double), sizeof(double) },
                { typeof(decimal), sizeof(decimal) },
                { typeof(bool), sizeof(bool) }
                };
        

        private GCHandle handle;

        private ulong byteCount;

        private bool virtualLocked;

        /// <summary>
        /// Initialize a new instance of the <see cref="SecureArray"/> class.
        /// </summary>
        /// <remarks>
        /// You cannot create a <see cref="SecureArray"/> directly, you must
        /// derive from this class like <see cref="SecureArray{T}"/> does.
        /// </remarks>
        protected SecureArray()
        {
        }

        /// <summary>
        /// Gets the size of the buffer element. Will throw a 
        /// <see cref="NotSupportedException"/> if the element type is not
        /// a built in type.
        /// </summary>
        /// <typeparam name="T">
        /// The array element type to return the size of.
        /// </typeparam>
        /// <param name="buffer">
        /// The array.
        /// </param>
        /// <returns></returns>
        public static int BuiltInTypeElementSize<T>(T[] buffer)
        {
            if (!TypeSizes.TryGetValue(typeof(T), out int elementSize))
            {
                throw new NotSupportedException(
                  $"Type {typeof(T).Name} not a built in type. "
                  + $"Valid types: {string.Join(", ", TypeSizes.Keys.Select(t => t.Name))}");
            }

            return elementSize;
        }

        /// <summary>
        /// Zero the given buffer in a way that will not be optimized away.
        /// </summary>
        /// <typeparam name="T">
        /// The type of the elements in the buffer.
        /// </typeparam>
        /// <param name="buffer">
        /// The buffer to zero.
        /// </param>
        public static void Zero<T>(T[] buffer)
            where T : struct
        {
            if (buffer != null)
            {
                var bufHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                try
                {
                    IntPtr bufPtr = bufHandle.AddrOfPinnedObject();
                    UIntPtr cnt = new UIntPtr(
                         (uint)buffer.Length * (uint)BuiltInTypeElementSize(buffer));
                    RtlZeroMemory(bufPtr, cnt);
                }
                finally
                {
                    bufHandle.Free();
                }
            }
        }

        
        /// <summary>
        /// Call this with the array to secure and the number of bytes in that
        /// array. The buffer will be zeroed and the handle freed when the
        /// instance is disposed.
        /// </summary>
        /// <param name="buf">
        /// The array to secure.
        /// </param>
        /// <param name="sizeInBytes">
        /// The number of bytes in the buffer in the pinned object.
        /// </param>
        /// <param name="noswap">
        /// True to lock the memory so it doesn't swap.
        /// </param>
        protected void Init<T>(T[] buf, long sizeInBytes, bool noswap)
        {
            handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            byteCount = (ulong)sizeInBytes;
            IntPtr bufPtr = handle.AddrOfPinnedObject();
            UIntPtr cnt = new UIntPtr(byteCount);
            if (noswap)
            {
                VirtualLock(bufPtr, cnt);
                virtualLocked = true;
            }
        }

        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr ptr, UIntPtr cnt);

        [DllImport("kernel32.dll")]
        static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll")]
        static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        /// <summary>
        /// Forces array to be cleared using RtlZeroMemory
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // dispose managed code
                }

                try
                {
                    IntPtr bufPtr = handle.AddrOfPinnedObject();
                    UIntPtr cnt = new UIntPtr(byteCount);

                    RtlZeroMemory(bufPtr, cnt);

                    if (virtualLocked)
                    {
                        VirtualUnlock(bufPtr, cnt);
                    }
                }
                finally
                {
                    handle.Free();
                }

                disposedValue = true;
            }
        }

        ~SecureArray()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // use if the finalizer is overridden above.
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
