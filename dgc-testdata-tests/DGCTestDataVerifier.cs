using DGC;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace dgc.testdata.tests
{
    public class DGCTestDataVerifier
    {
        record TestData(string prefix, string certificate, string filename);

        public record EXPECTEDRESULTS(bool EXPECTEDVALIDOBJECT, bool EXPECTEDSCHEMAVALIDATION, bool EXPECTEDENCODE,
            bool EXPECTEDDECODE, bool EXPECTEDVERIFY, bool EXPECTEDCOMPRESSION,
            bool EXPECTEDKEYUSAGE, bool EXPECTEDUNPREFIX, bool EXPECTEDVALIDJSON,
            bool EXPECTEDB45DECODE, bool EXPECTEDPICTUREDECODE, bool EXPECTEDEXPIRATIONCHECK);
        public record TESTCTX(string VERSION, string SCHEMA, string CERTIFICATE, DateTime VALIDATIONCLOCK, string DESCRIPTION);
        public record TestDataStructure(JObject JSON, string CBOR, string COSE, string COMPRESSED, string BASE45, string PREFIX, string x2DCODE, TESTCTX TESTCTX, EXPECTEDRESULTS EXPECTEDRESULTS);

        public void TestAll()
        {
            var jsonfiles = Directory.GetFiles("dgc-testdata", "*.json", SearchOption.AllDirectories);

            var testdataset = new List<Tuple<TestDataStructure,string>>();
            foreach (var jsonTestDataFile in jsonfiles)
            {
                using var file = File.OpenText(jsonTestDataFile);
                try
                {
                    var test = JsonConvert.DeserializeObject<TestDataStructure>(file.ReadToEnd());
                    testdataset.Add(Tuple.Create(test, jsonTestDataFile));
                }
                catch (Exception)
                {
                }
            }

            var parser = new X509CertificateParser();
            var dcgDecoder = new GreenCertificateDecoder();
            var secretariat = new SecretariatService();
            var verifier = new GreenCertificateVerifier(secretariat);
            foreach (var testdataAndFile in testdataset)
            {
                var testdata = testdataAndFile.Item1;
                try
                {
                    var cwt = dcgDecoder.Decode(testdata.PREFIX);
                    if (!secretariat.GetCertificate(cwt.CoseMessage.KID).Any())
                    {
                        var certBytes = Convert.FromBase64String(testdata.TESTCTX.CERTIFICATE);
                        var x509certificate = parser.ReadCertificate(certBytes);
                        secretariat.AddPublicKey(cwt.CoseMessage.KID, x509certificate);
                    }

                    var (isvalid, reason) = verifier.Verify(cwt);
                    //Assert.IsTrue(isvalid, reason);
                }
                catch (Exception ex)
                {
                }
            }
        }
    }
}
