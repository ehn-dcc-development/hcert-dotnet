using dgc.Valuesets;
using DGC;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace dgc.tests
{
    [TestClass]
    public class MrzEncoderTests
    {
        [TestMethod]
        public void MrzEncoder_TEST()
        {
            Assert.AreEqual("THETTA<ER<AD<PROFA", MrzEncoder.Encode("Þetta er að prófa"));
        }
    }
}
