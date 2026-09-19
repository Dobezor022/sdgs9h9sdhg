using FedMes.Desktop.Core.Domain;

namespace FedMes.Desktop.Tests.Domain;

[TestClass]
public sealed class FixedFamilyUsersTests
{
    [TestMethod]
    public void AllContainsExactlyTheConfiguredFamily()
    {
        string[] expected = ["grisha", "papa", "mama", "yura", "vasya"];

        CollectionAssert.AreEqual(expected, FixedFamilyUsers.All);
    }

    [TestMethod]
    [DataRow("grisha")]
    [DataRow("papa")]
    [DataRow("mama")]
    [DataRow("yura")]
    [DataRow("vasya")]
    public void IsAllowedAcceptsConfiguredUser(string userName)
    {
        Assert.IsTrue(FixedFamilyUsers.IsAllowed(userName));
    }

    [TestMethod]
    [DataRow("Grisha")]
    [DataRow(" grisha")]
    [DataRow("grisha ")]
    [DataRow("admin")]
    [DataRow("")]
    public void IsAllowedRejectsAnythingOutsideTheExactPolicy(string userName)
    {
        Assert.IsFalse(FixedFamilyUsers.IsAllowed(userName));
    }

    [TestMethod]
    public void IsAllowedRejectsNull()
    {
        Assert.IsFalse(FixedFamilyUsers.IsAllowed(null));
    }
}
