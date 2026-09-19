using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.Tests.Messaging;

[TestClass]
public sealed class TextFormattingTests
{
    private static readonly TextEntity[] OriginalBold = [new(TextEntityType.Bold, 0, 4)];
    private static readonly TextEntity[] OriginalItalic = [new(TextEntityType.Italic, 2, 4)];
    private static readonly TextEntity[] ExpectedBold = [new(TextEntityType.Bold, 0, 5)];
    private static readonly TextEntity[] ExpectedItalic = [new(TextEntityType.Italic, 0, 4)];

    [TestMethod]
    public void Toggle_Adds_And_Removes_Format()
    {
        IReadOnlyList<TextEntity> added = TextFormatting.Toggle("alpha beta", Array.Empty<TextEntity>(), TextEntityType.Bold, 0, 5);
        CollectionAssert.AreEqual(ExpectedBold, added.ToArray());
        Assert.AreEqual(0, TextFormatting.Toggle("alpha beta", added, TextEntityType.Bold, 0, 5).Count);
    }

    [TestMethod]
    public void Spoiler_Format_Can_Be_Toggled()
    {
        IReadOnlyList<TextEntity> added = TextFormatting.Toggle("secret", Array.Empty<TextEntity>(), TextEntityType.Spoiler, 0, 6);
        Assert.AreEqual(TextEntityType.Spoiler, added.Single().Type);
        Assert.AreEqual(0, TextFormatting.Toggle("secret", added, TextEntityType.Spoiler, 0, 6).Count);
    }

    [TestMethod]
    public void RemapAfterEdit_Extends_Entity_For_Insertion()
    {
        IReadOnlyList<TextEntity> result = TextFormatting.RemapAfterEdit(
            "bold",
            "boXld",
            OriginalBold);
        CollectionAssert.AreEqual(ExpectedBold, result.ToArray());
    }

    [TestMethod]
    public void Normalize_Trims_Offsets()
    {
        NormalizedFormattedText result = TextFormatting.Normalize(
            "  text  ",
            OriginalItalic);
        Assert.AreEqual("text", result.Text);
        CollectionAssert.AreEqual(ExpectedItalic, result.Entities.ToArray());
    }
}
