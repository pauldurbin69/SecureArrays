using SecureArrays;
using System;
using System.Security.Cryptography;

namespace EncryptedSecret
{
    /// <summary>
    /// Long term in-memory secure encrypted storage of secrets 
    /// </summary>
    public sealed class DpapiEncryptedByteArray: IDisposable
    {
        private readonly byte[] _additionalEntropy = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };
        private readonly byte[] _protecteBytes;

        public int UnencryptedDatalength { get; private set; }

        /// <summary>
        /// Protect data with dpapi 
        /// Will zero out plain text data
        /// </summary>
        /// <param name="plainTextData"></param>
        public DpapiEncryptedByteArray(SecureArray<byte> plainTextData): this(plainTextData.Buffer)
        {
        }

        /// <summary>
        /// Protect data with dpapi 
        /// Will zero out plain text data
        /// </summary>
        /// <param name="plainTextData"></param>
        public DpapiEncryptedByteArray(byte[] plainTextData)
        {
            if (plainTextData == null)
            {
                throw new ArgumentNullException(nameof(plainTextData));
            }

            UnencryptedDatalength = plainTextData.Length;

            try 
            {
                _protecteBytes = ProtectedData.Protect(plainTextData, _additionalEntropy, DataProtectionScope.CurrentUser);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("failed to retrieve protected data", ex);
            }
            finally
            {
                SecureArray.Zero(plainTextData);
            }
        }

        /// <summary>
        /// Unprotect data from dpapi storage to a secure array with cleatext bytes
        /// </summary>
        /// <returns></returns>
        public SecureArray<byte> ToSecureArray()
        {
            return ProtectedData.Unprotect(_protecteBytes, _additionalEntropy, DataProtectionScope.CurrentUser).ToSecureArray();
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    SecureArray.Zero(_protecteBytes);
                }

                disposedValue = true;
            }
        }
        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
