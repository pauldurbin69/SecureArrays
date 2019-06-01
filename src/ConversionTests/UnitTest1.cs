using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace ConversionTests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestSecureStringConvert()
        {
            var plaintext = "password123";

            var ss = plaintext.ToSecureString();

            var sec = ss.ToEncryptedArray();

            var ss2 = sec.ToSecureString();

            var plaintext2 = ss2.ToPlainTextString();

            Assert.AreEqual(plaintext, plaintext2);

        }
    }
}
