using SecureArrays;
using System;
using System.Collections.Generic;
using System.Text;

namespace System
{
    public static class Extensions
    {
        /// <summary>
        /// Convert array to a secure array
        /// will zero array passed in using RtlZeroMemory
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="array"></param>
        /// <returns></returns>
        public static SecureArray<T> ToSecureArray<T>(this T[] array) where T : struct
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            try
            {
                var secure = new SecureArray<T>(array.Length);

                Buffer.BlockCopy(array, 0, secure.Buffer, 0, array.Length);

                return secure;
            }
            finally
            {
                SecureArray.Zero(array);
            }
        }
    }
}
