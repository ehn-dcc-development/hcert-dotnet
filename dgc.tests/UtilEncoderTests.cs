using DCC;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DGC.Tests
{
    [TestClass]
    public class UtilEncoderTests
    {
        [TestMethod]
        public void MrzEncoder_TEST()
        {
            Assert.AreEqual("THETTA<ER<AD<PROFA", MrzEncoder.Encode("Þetta er að prófa"));
        }

        [TestMethod]
        public void LuahModN_TEST()
        {
            Assert.AreEqual('Z', LuhnModN.GenerateCheckCharacter("URN:UVCI:01:NL:187/37512422923"));
        }
    }
}
