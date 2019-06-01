using EncryptedSecret;
using SecureArrays;

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
        public static DpapiEncryptedByteArray ToSecureBytes(this byte[] array) 
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }
           
            // constructor clears array on creation
            return new DpapiEncryptedByteArray(array);
        }

        public static DpapiEncryptedByteArray ToSecureBytes(this SecureArray<byte> secureArray)
        {
            if (secureArray == null)
            {
                throw new ArgumentNullException(nameof(secureArray));
            }

            // constructor clears array on creation
            return new DpapiEncryptedByteArray(secureArray);
        }
    }
}
