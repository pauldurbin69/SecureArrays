using EncryptedSecret;
using SecureArrays;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;

namespace System
{
    [SuppressUnmanagedCodeSecurity]
    public static class Extensions
    {
        /// <summary>
        /// Convert plaintext string to SecureString
        /// Please be aware that the plaintext string can not be removed from memory
        /// Please make user of as SecureArray<byte> SecureArray<char> or DpapiEncryptedByteArray
        /// to enable better in-memory protection for your secret
        /// </summary>
        /// <param name="plainString"></param>
        /// <returns></returns>
        public static SecureString ToSecureString(this string plainString)
        {
            if (string.IsNullOrEmpty(plainString))
            {
                return new SecureString();
            }

            return ToSecureString(plainString.ToArray());
        }

        /// <summary>
        /// Convert a DpApi protected byte[] to SecureString
        /// </summary>
        /// <param name="encryptedString"></param>
        /// <returns></returns>
        public static SecureString ToSecureString(this DpapiEncryptedByteArray encryptedString)
        {
            return ToSecureString(encryptedString.ToSecureArray().Buffer.Select(b => (char)b).ToArray());
        }

        /// <summary>
        /// Convert a SecureArray<byte> to SecureString
        /// </summary>
        /// <param name="plainString"></param>
        /// <returns></returns>
        public static SecureString ToSecureString(this SecureArray<byte> plainString)
        {
            using (plainString)
            {
                return ToSecureString(plainString.Buffer.Cast<char>().ToArray());
            }
        }

        /// <summary>
        /// Convert char[] to SecureString
        /// </summary>
        /// <param name="plainString"></param>
        /// <returns></returns>
        public static unsafe SecureString ToSecureString(this char[] plainString)
        {
            SecureString str;

            try
            {
                if (plainString == null || !plainString.Any())
                {
                    return new SecureString();
                }
                fixed (char* str2 = plainString)
                {
                    char* chPtr = str2;
                    str = new SecureString(chPtr, plainString.Length);
                    str.MakeReadOnly();
                }
                return str;
            }
            finally
            {
                SecureArray.Zero(plainString);
            }
        }

        /// <summary>
        /// Convert Securestring to an DpApi encrypted byte[]
        /// </summary>
        /// <param name="secureString"></param>
        /// <returns></returns>
        public static DpapiEncryptedByteArray ToEncryptedArray(this SecureString secureString)
        {
            IntPtr zero = IntPtr.Zero;
            if ((secureString == null) || (secureString.Length == 0))
            {
                return null;
            }
            try
            {
                // unicode so twice as big
                using (var secureArray = new SecureArray<byte>(secureString.Length))
                {
                    zero = Marshal.SecureStringToGlobalAllocAnsi(secureString);
                    Marshal.Copy(zero, secureArray.Buffer, 0, secureString.Length);

                    return secureArray.ToSecureBytes();
                }
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocAnsi(zero);
                }
            }
        }

        /// <summary>
        /// Should only use this as a last resort as .Net strings are not at all secure
        /// </summary>
        /// <param name="secureString"></param>
        /// <returns></returns>
        public static string ToPlainTextString(this SecureString secureString)
        {
            string str;
            IntPtr zero = IntPtr.Zero;
            if ((secureString == null) || (secureString.Length == 0))
            {
                return string.Empty;
            }
            try
            {
                zero = Marshal.SecureStringToBSTR(secureString);
                str = Marshal.PtrToStringBSTR(zero);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(zero);
                }
            }
            return str;
        }
    }
}
