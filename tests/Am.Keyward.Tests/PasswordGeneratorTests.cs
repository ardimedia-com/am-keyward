using Am.Keyward.Core.Support;

namespace Am.Keyward.Tests;

[TestClass]
public class PasswordGeneratorTests
{
    [TestMethod, TestCategory("Unit")]
    public void Every_password_has_the_length_and_all_four_character_classes()
    {
        for (var i = 0; i < 500; i++)
        {
            var password = PasswordGenerator.Generate();
            Assert.HasCount(PasswordGenerator.DefaultLength, password);
            Assert.IsTrue(password.Any(char.IsUpper), password);
            Assert.IsTrue(password.Any(char.IsLower), password);
            Assert.IsTrue(password.Any(char.IsDigit), password);
            Assert.IsTrue(password.Any(c => !char.IsLetterOrDigit(c)), password);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void No_confusable_or_breaking_characters()
    {
        var all = string.Concat(Enumerable.Range(0, 300).Select(_ => PasswordGenerator.Generate(PasswordGenerator.MaximumLength)));
        foreach (var forbidden in "0Oo1lI\"'`\\;: ()[]{}<>/|,.")
        {
            Assert.DoesNotContain(forbidden.ToString(), all);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void Passwords_differ_and_the_length_is_bounded()
    {
        var passwords = Enumerable.Range(0, 1000).Select(_ => PasswordGenerator.Generate()).ToHashSet();
        Assert.HasCount(1000, passwords);
        Assert.HasCount(32, PasswordGenerator.Generate(32));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => PasswordGenerator.Generate(PasswordGenerator.MinimumLength - 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => PasswordGenerator.Generate(PasswordGenerator.MaximumLength + 1));
    }
}
