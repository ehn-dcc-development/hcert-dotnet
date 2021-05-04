using DGC;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace dgc.tests.testdata
{
    [TestClass]
    public class DGCTestDataVerifier
    {


        record TestData (string prefix, string certificate);

        [TestMethod]
        public void TestAll()
        {
            var jsonfiles = Directory.GetFiles("testdata\\", "*.json", SearchOption.AllDirectories);

            var testdataset = new List<TestData>();
            foreach (var jsonTestDataFile in jsonfiles)
            {
                using var file = File.OpenText(jsonTestDataFile);
                using var reader = new JsonTextReader(file);
                
                var o2 = (JObject)JToken.ReadFrom(reader);

                var prefix = o2["PREFIX"].ToString();
                var certificate = o2["TESTCTX"]["CERTIFICATE"].ToString();

                testdataset.Add(new TestData(prefix, certificate));
            }

            var parser = new X509CertificateParser();
            var dcgDecoder = new GreenCertificateDecoder();
            var secretariat = new SecretariatService();
            var verifier = new GreenCertificateVerifier(secretariat);
            foreach (var testdata in testdataset)
            {
                var cwt = dcgDecoder.Decode(testdata.prefix);
                if (!secretariat.GetPublicKeys(cwt.CoseMessage.KID).Any())
                {
                    var certBytes = Convert.FromBase64String(testdata.certificate);
                    var x509certificate = parser.ReadCertificate(certBytes);
                    secretariat.AddPublicKey(cwt.CoseMessage.KID, x509certificate.GetPublicKey());
                }

                var (isvalid, reason) = verifier.Verify(cwt);
            }
        }
    }
}
