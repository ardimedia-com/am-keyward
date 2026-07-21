using Am.Keyward.Core.Support;

namespace Am.Keyward.Tests;

[TestClass]
public class Base62GuidTests
{
    [TestMethod, TestCategory("Domain")]
    public void Encode_is_fixed_length_and_has_no_word_break_chars()
    {
        var code = Base62Guid.Encode(Guid.NewGuid());
        Assert.AreEqual(Base62Guid.Length, code.Length);
        Assert.IsFalse(code.Contains('-'), "a Base62 id must not contain '-' (it would break double-click copy)");
        Assert.IsFalse(code.Contains('_'));
        Assert.IsTrue(code.All(char.IsLetterOrDigit));
    }

    [TestMethod, TestCategory("Domain")]
    public void Roundtrips_any_guid_including_empty_and_max()
    {
        foreach (var g in new[] { Guid.Empty, new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff"), Guid.NewGuid(), Guid.NewGuid() })
        {
            var code = Base62Guid.Encode(g);
            Assert.IsTrue(Base62Guid.TryDecode(code, out var back), $"decode failed for {g}");
            Assert.AreEqual(g, back);
        }
    }

    [TestMethod, TestCategory("Domain")]
    public void Empty_guid_encodes_to_all_zero_padded_id()
    {
        Assert.AreEqual(new string('0', Base62Guid.Length), Base62Guid.Encode(Guid.Empty));
    }

    [TestMethod, TestCategory("Domain")]
    public void TryDecode_rejects_malformed_input()
    {
        Assert.IsFalse(Base62Guid.TryDecode(null, out _));
        Assert.IsFalse(Base62Guid.TryDecode("", out _));
        Assert.IsFalse(Base62Guid.TryDecode("tooshort", out _));
        Assert.IsFalse(Base62Guid.TryDecode(new string('0', Base62Guid.Length - 1), out _)); // wrong length
        Assert.IsFalse(Base62Guid.TryDecode("-" + new string('0', Base62Guid.Length - 1), out _)); // out-of-alphabet char
        Assert.IsFalse(Base62Guid.TryDecode(new string('z', Base62Guid.Length), out _)); // exceeds 128 bits
    }
}
