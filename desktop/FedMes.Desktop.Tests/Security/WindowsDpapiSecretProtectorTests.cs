using System.Security.Cryptography;
using System.Text;
using FedMes.Desktop.Core.Security;

namespace FedMes.Desktop.Tests.Security;

[TestClass]
public sealed class WindowsDpapiSecretProtectorTests
{
    [TestMethod]
    public void ProtectAndUnprotectRoundTripsForCurrentWindowsUser()
    {
        var protector = new WindowsDpapiSecretProtector();
        byte[] plaintext = Encoding.UTF8.GetBytes("test-account-secret");
        byte[]? protectedData = null;
        byte[]? recovered = null;

        try
        {
            protectedData = protector.Protect(plaintext);
            recovered = protector.Unprotect(protectedData);

            Assert.IsFalse(plaintext.SequenceEqual(protectedData));
            CollectionAssert.AreEqual(plaintext, recovered);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedData is not null)
            {
                CryptographicOperations.ZeroMemory(protectedData);
            }

            if (recovered is not null)
            {
                CryptographicOperations.ZeroMemory(recovered);
            }
        }
    }

    [TestMethod]
    public void UnprotectWithDifferentPurposeIsRejected()
    {
        var writer = new WindowsDpapiSecretProtector("FedMes.Tests.ContextA");
        var reader = new WindowsDpapiSecretProtector("FedMes.Tests.ContextB");
        byte[] plaintext = [1, 2, 3, 4, 5];
        byte[]? protectedData = null;

        try
        {
            protectedData = writer.Protect(plaintext);
            Assert.ThrowsExactly<CryptographicException>(() => reader.Unprotect(protectedData));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedData is not null)
            {
                CryptographicOperations.ZeroMemory(protectedData);
            }
        }
    }

    [TestMethod]
    public void ProtectRejectsEmptySecret()
    {
        var protector = new WindowsDpapiSecretProtector();

        Assert.ThrowsExactly<ArgumentException>(() => protector.Protect([]));
    }
}
