using FedMes.Desktop.Core.Security;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Tests.Storage;

[TestClass]
public sealed class DesktopAccountStoreTests
{
    [TestMethod]
    public void SaveLoadAndClearRoundTripsAccount()
    {
        string directory = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "account.json");
        try
        {
            var store = new DesktopAccountStore(new CopyProtector(), path);
            var expected = new DesktopAccount(
                "https://fedmes.example",
                "grisha",
                "device-id",
                "session-id",
                "session-token",
                new DateTimeOffset(2026, 7, 13, 12, 15, 0, TimeSpan.Zero),
                "Desktop · STUDIO-PC");
            store.Save(expected);
            Assert.AreEqual(expected, store.Load());
            store.Clear();
            Assert.IsNull(store.Load());
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }


    [TestMethod]
    public void CandidateDoesNotReplaceActiveAccountUntilPromotion()
    {
        string directory = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "account.json");
        try
        {
            var store = new DesktopAccountStore(new CopyProtector(), path);
            var active = new DesktopAccount(
                "https://fedmes.example", "grisha", "active-device", "active-session", "active-token",
                DateTimeOffset.UtcNow.AddMinutes(15), "Active desktop", "READY");
            var candidate = new DesktopAccount(
                "https://fedmes.example", "papa", "candidate-device", "candidate-session", "candidate-token",
                DateTimeOffset.UtcNow.AddMinutes(15), "Candidate desktop", "AUTHENTICATED_NO_KEYS");

            store.Save(active);
            store.SaveCandidate(candidate);
            Assert.AreEqual(active, store.Load());
            Assert.AreEqual(candidate, store.LoadCandidate());

            DesktopAccount ready = candidate with { AuthenticationState = "READY" };
            store.PromoteCandidate(ready);
            Assert.AreEqual(ready, store.Load());
            Assert.IsNull(store.LoadCandidate());
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [TestMethod]
    public void LoadRejectsAnOversizedLocalStateFileBeforeParsing()
    {
        string directory = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "account.json");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllBytes(path, new byte[64 * 1024 + 1]);
            var store = new DesktopAccountStore(new CopyProtector(), path);

            Assert.ThrowsExactly<InvalidDataException>(() => store.Load());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [TestMethod]
    public void FailedAtomicCommitRemovesItsTemporaryFile()
    {
        string directory = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "account.json");
        Directory.CreateDirectory(path);
        try
        {
            var store = new DesktopAccountStore(new CopyProtector(), path);
            var account = new DesktopAccount(
                "https://fedmes.example",
                "grisha",
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                "session-token",
                DateTimeOffset.UtcNow.AddMinutes(15),
                "Desktop test");

            Assert.ThrowsExactly<UnauthorizedAccessException>(() => store.Save(account));

            Assert.AreEqual(0, Directory.GetFiles(directory, ".account.json.*.tmp").Length);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class CopyProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData) => protectedData.ToArray();
    }
}
