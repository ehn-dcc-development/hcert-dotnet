using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PeterO.Cbor;

namespace DGC.Tests
{
    [TestClass]
    public class UnitTest1
    {
        private static CWT CreateCWTTestData()
        {
            var tests = new List<TestEntry>
            {
                new TestEntry
                {
                    CountryOfTest = "IS",
                    TestName ="PCR Covid-19"
                }
            };

            var vacs = new List<VaccinationEntry>
            {
                new VaccinationEntry
                {
                    Issuer ="Test Issuer"
                }
            };

            CWT cwt = new CWT();
            cwt.DGCv1 = new DgCertificate
            {
                Name = new Nam
                {
                    FamilyName = "Testson",
                    GivenName = "Test"
                },
                Test = tests.ToArray(),
                Vaccination = vacs.ToArray()
            };

            cwt.ExpiarationTime = DateTime.Now.AddDays(7);
            cwt.IssueAt = DateTime.Now;
            cwt.Issuer = "DNK";

            return cwt;
        }

        [TestMethod]
        public void EncodeDecode_RoundTrip_IsValid()
        {
            var random = new SecureRandom();
            var keyGenerationParameters = new KeyGenerationParameters(random, 256);
            var generator = new ECKeyPairGenerator();
            generator.Init(keyGenerationParameters);
            var keypair = generator.GenerateKeyPair();

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keypair.Public);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            var keyid = Convert.ToBase64String(serializedPublicBytes).Substring(0, 8);

            var cwtToTest = CreateCWTTestData();
            string encoded = new GreenCertificateEncoder(keypair, keyid).Encode(cwtToTest);
            var cwt = new GreenCertificateDecoder().Decode(encoded);

            var scretariat = new SecretariatService();
            scretariat.AddPublicKey(keypair.Public);

            var verifier = new GreenCertificateVerifier(scretariat);
            var (isvalid, _) = verifier.Verify(cwt);

            Assert.IsTrue(isvalid);
            Assert.IsTrue(JToken.DeepEquals(JToken.Parse(JsonSerializer.Serialize(cwtToTest.DGCv1)), JToken.Parse(JsonSerializer.Serialize(cwt.DGCv1))));
        }

        [TestMethod]
        public void EncodeDecode_WrongPublicKey()
        {
            var random = new SecureRandom();
            var keyGenerationParameters = new KeyGenerationParameters(random, 256);
            var generator = new ECKeyPairGenerator();
            generator.Init(keyGenerationParameters);
            var keypair = generator.GenerateKeyPair();

            var cborPrivateKey = keypair.Private;

            generator.Init(keyGenerationParameters);
            var keypairWrongPub = generator.GenerateKeyPair();
            var cborPublicKey = keypairWrongPub.Public;

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keypair.Public);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            var keyid = Convert.ToBase64String(serializedPublicBytes).Substring(0, 8);

            var cwtToTest = CreateCWTTestData();

            string encoded = new GreenCertificateEncoder(keypair, keyid).Encode(cwtToTest);
            var cwt = new GreenCertificateDecoder().Decode(encoded);

            var scretariat = new SecretariatService();
            scretariat.AddPublicKey(cborPublicKey);

            var verifier = new GreenCertificateVerifier(scretariat);
            var (isvalid, reason) = verifier.Verify(cwt);

            Assert.IsNotNull(reason);
            Assert.IsFalse(isvalid);
            Assert.IsTrue(JToken.DeepEquals(JToken.Parse(JsonSerializer.Serialize(cwtToTest.DGCv1)), JToken.Parse(JsonSerializer.Serialize(cwt.DGCv1))));
        }

        [TestMethod]
        public void EncodeDecode_RSAKeys()
        {
            var random = new SecureRandom();
            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
            var generator = new RsaKeyPairGenerator();
            generator.Init(keyGenerationParameters);
            var keypair = generator.GenerateKeyPair();


            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keypair.Public);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            var keyid = Convert.ToBase64String(serializedPublicBytes).Substring(0, 8);

            var cwtToTest = CreateCWTTestData();
            string encoded = new GreenCertificateEncoder(keypair, keyid).Encode(cwtToTest);
            var cwt = new GreenCertificateDecoder().Decode(encoded);

            var scretariat = new SecretariatService();
            scretariat.AddPublicKey(keypair.Public);

            var verifier = new GreenCertificateVerifier(scretariat);
            var (isvalid, _) = verifier.Verify(cwt);

            Assert.IsTrue(isvalid);
            Assert.IsTrue(JToken.DeepEquals(JToken.Parse(JsonSerializer.Serialize(cwtToTest.DGCv1)), JToken.Parse(JsonSerializer.Serialize(cwt.DGCv1))));
        }

        [TestMethod]
        public void DecodeTest_VaccinationECKey()
        {
            string coseBase45 = "HC1:NCFOXN%TS3DHZN4HAF*PQFKKGTNA.Q/R8WRU2FCGJ9S8F7XHNH5/9SOWHPJPC%OQHIZC4.OI1RM8ZA.A53XHMKN4NN3F85QNCY0O%0VZ001HOC9JU0D0HT0HO1PM:K$$09B9LW4T*8+DC%H0PZBITH$*SBAKYE9*FJTJAHD4UDADPSDJIM4KF/B0C2SFIH:9$GCQOS62PR6WPHN6D7LLK*2HG%89UV-0LZ 2ZJJ4FF86O:HO73SM1IO-O.Z80GHS-O:S9UZ4+FJE 4Y3LL/II 07LPMIH-O9XZQSH9R$FXQGDVBK*RZP3:*DG1W7SGT$7S%RMSG2UQYI9*FGCPAXRQ3E2N+E .1:L7O:7X/5Q+MSA7G6MBYO+JQLHP71RJW63X7VUONC6V35HW6SZ6FT5D75W9AV88E34+V4YC5/HQWOQ6$S4N4N31229/J3O5JY7KVP7G/LINT40Q$OI1Y4B7G3FE*2UV5O N5TD8CMRCSF1LR4ZQLTE56QQ2MRZ3HXCKQR7HAWKMDSI9MJO%18I962G16B.40G6IG5";

            var decoder = new GreenCertificateDecoder();

            var cwt = decoder.Decode(coseBase45);

            Assert.IsNotNull(cwt);
            Assert.IsNotNull(cwt.DGCv1.Vaccination);
            Assert.AreEqual(cwt.CoseMessage.RegisteredAlgorithm, HCertSupportedAlgorithm.ES256);

            /*

            var filecontent = File.ReadAllBytes("list");
            var certlist = CBORObject.DecodeFromBytes(filecontent);
            
            
            var scs = new SecretariatService();

            string pem = @"-----BEGIN CERTIFICATE-----
MIIBJTCBy6ADAgECAgUAwvEVkzAKBggqhkjOPQQDAjAQMQ4wDAYDVQQDDAVFQy1N
ZTAeFw0yMTA0MjMxMTI3NDhaFw0yMTA1MjMxMTI3NDhaMBAxDjAMBgNVBAMMBUVD
LU1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/OV5UfYrtE140ztF9jOgnux1
oyNO8Bss4377E/kDhp9EzFZdsgaztfT+wvA29b7rSb2EsHJrr8aQdn3/1ynte6MS
MBAwDgYDVR0PAQH/BAQDAgWgMAoGCCqGSM49BAMCA0kAMEYCIQC51XwstjIBH10S
N701EnxWGK3gIgPaUgBN+ljZAs76zQIhAODq4TJ2qAPpFc1FIUOvvlycGJ6QVxNX
EkhRcgdlVfUb
-----END CERTIFICATE-----";
            var pr = new PemReader(new StringReader(pem));
            var certificate = (X509Certificate) pr.ReadObject();
            var publicKey = certificate.GetPublicKey();
            scs.AddPublicKey(publicKey);
            var verifier = new GreenCertificateVerifier(scs);
            var (isValid, reason) = verifier.Verify(cwt);

            Assert.IsTrue(isValid, reason);*/
        }


        record TestData(string encodedEhnCert, string keyId, string encodedSigningCert, bool shouldFale = false);

        static List<TestData> testData = new List<TestData>
        {
            new TestData(encodedEhnCert: "HC1:NCFOXN%TS3DHZN4HAF*PQFKKGTNA.Q/R8WRU2FC6L9N*CH PC.IU:N AJPJPC%OQHIZC4.OI1RM8ZA.A53XHMKN4NN3F85QNCY0O%0VZ001HOC9JU0D0HT0HO1PM:K$$09B9LW4T*8+DC%H0PZBITH$*SBAKYE9*FJTJAHD4UDADPSDJIM4KF/B0C2SFIH:9$GCQOS62PR6WPHN6D7LLK*2HG%89UV-0LZ 2ZJJ4FF86O:HO73SM1IO-O.Z80GHS-O:S9UZ4+FJE 4Y3LL/II 07LPMIH-O9XZQSH9R$FXQGDVBK*RZP3:*DG1W7SGT$7S%RMSG2UQYI9*FGCPAXRQ3E2N+E .1:L7O:7X/5Q+MSA7G6MBYO+JQLHP71RJW63X7VUONC6V35HW6SZ6FT5D75W9AV88E34+V4YC5/HQWOQ6$S4N4N31SHPO3Q0E447H9VAK:6.5G$N3ZF7W2SBJT7QG+8UJII3MACIBG2U76MGX3$YB.S7PIJRVOBTN6DTEUIOS7ZKJJEL%.B PT2LO36KT8SP50M/O$4", keyId: "", encodedSigningCert: "MIIBIzCByqADAgECAgRi5XwLMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBUVDLU1lMB4XDTIxMDQyMzEwMzc1NVoXDTIxMDUyMzEwMzc1NVowEDEOMAwGA1UEAwwFRUMtTWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT4pyqh0AMFtrN/rLF4tKBB+Rhp6ttuC6JTQ4c4fIy9f6H/Hjko8v6fYWkz3WrhKV7e0ScI4RLbT6nrv/F/6sJQoxIwEDAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSAAwRQIhAMQjFFnmgFx1scLH6+iY9Vyu3EYkHEzNXUv7Zr/H6gJDAiAw7Sry/U7h/X+Hk1MncAqln7dpK2MDKABc46ByFwZ+Bw==")
/*
            new TestData(encodedEhnCert: "HC1:NCFOXN%TS3DH0ZS2F97O2RXO5Y5CID:D4I$B%CM*Y4OBO*ZOJ*IMANZ9HPJPC%OQHIZC4VRMRPI:OI1%A395O.OAHA5VRCPIUF2FVPQJAZM93$UWW2QRA H99QHYOOQRA5RUXT25SIOH66L6SR9MU9DV5 R18AGZKHBKB3YUCIG%X4+$SS/CLS4:35HFER/F//CTIIH+G260H23+5JH$2.FV5DJ5DJBITEP47*KH-2.C30$9:Q6300AL8GWKSMIMXAH:O/B9/UIQRAFTQ2JATK2YJADG6JD3YW4:3TLD37UJBG7ME7ND33836:IOS0LS400T*OVAZ2M$BO.A29BLZI19JA2K7VA$IJVTIWZJ$7K+ CUEDDIKZ9C.PDH0JW1JY*R/8BN-A1DLNCKQ20HT8NN8VI9 KE.I90QN5IKXBHLII3.K$JL4HG9LN$II-GG0JIBHH.HIEKNTII7JJ-92$P6JD1F671NI+*RPKAOSHB.IUK96QF1%1RMN661V+JW29:VB/8TEXOV8O/DR-Z644SCL9U-LV5UD2MQAE5PTDRAP17+6D$P8HVK7DMZ5H$VPT406H5K5", keyId: "8TRqlBQxUbQ", encodedSigningCert: "MIIBIzCByqADAgECAgQbc6tlMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBUVDLU1lMB4XDTIxMDQyMDA3Mjg1MVoXDTIxMDUyMDA3Mjg1MVowEDEOMAwGA1UEAwwFRUMtTWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASAnF9trnoiLJxV8zkWDCv4jM9/ls3bC5vVt/+oXkgHCOndb7e/7stg1OP64Gh3l/k64MlTBdR448bQA1IPXgOcoxIwEDAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSAAwRQIgcRqHvybuL5WlAlNusu++a+cR1onTcj9VeH9ymNsFnQUCIQDfs95vijEGiXZEz2D8LF2umf1zBHvTo2s9u8EW92NypA=="),
            new TestData(encodedEhnCert: "HC1:NCFD:MFY7N/Q.53VEEWRH7ATC3NY5F*DKNBV04E/IE/ZGM:MS1FA7RR4RA/4VDTTJPJ848DRR*S*:2GG90P2PL7THV$ZMDB8Q7EESNKT5X97G090R8 2DO$BK-R0245.VW.1D-J5OSCCU+ZNXSP42O% 4W*L28KKQ1WIPTDSE%FX:2J6O/LCW7V96DN%FTWD6.5BH5I+I2I9R+IPHK6 8FTCFXB$22CSOEPM:$VF M784PMB71OIWMMPALHBPCCYI5B.PK-P$CBXF5%S2WG6:3K.NJL$4P Q/YEEC7V24DQ3U 2TBA9XEB1D+JAP%5LOCLIAY 4HBD-UN3 PHXUEES:XJG/KHK67TM3H0ZK1MEERYA*B7F4MCLJK$9TMQPIA4%68DH GP+FGN%3KO8H5BH941MEN*9/OJHQG:K6S30B98Y63P P8OHOZKK$7IAS$Q8Z.8X0WCE6$J1UFJ56GBS8P-TUD9VN0SR2UPLLN9E469F0J.NNO4QT3240Q57F8C:TP1 M3DGRMSIWK7MRF9WC1S5RJ4 FT TGLV3WMK5I6MF+RGZ:NNQU9ARK2G7D7%+8I8S$2U7%INWK8RFW5ELQRMKTD6763D 1G-HOL$V*7HTN752E%O7:CFU.2WM365", keyId: "8TRqlBQxUbQ", encodedSigningCert: "MIIBIzCByqADAgECAgQbc6tlMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBUVDLU1lMB4XDTIxMDQyMDA3Mjg1MVoXDTIxMDUyMDA3Mjg1MVowEDEOMAwGA1UEAwwFRUMtTWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASAnF9trnoiLJxV8zkWDCv4jM9/ls3bC5vVt/+oXkgHCOndb7e/7stg1OP64Gh3l/k64MlTBdR448bQA1IPXgOcoxIwEDAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSAAwRQIgcRqHvybuL5WlAlNusu++a+cR1onTcj9VeH9ymNsFnQUCIQDfs95vijEGiXZEz2D8LF2umf1zBHvTo2s9u8EW92NypA=="),
            new TestData(encodedEhnCert: "HC1:NCFOXN%TS3DH0ZS2F97O2RXO5Y5CIDDH4%%5OGI+MHY5EM*489A+OFKQCAQCCV4*XUT3PDJPO-OJX1H:O/B9/UIQRAFTQ2JATK2YJADG6JD3YW4:3TLD37UJBG7ME7ND33836:IOS0LS400T*OVN%2LXK6*K$X4%*4HBTSCNT 4C%C47T+*4.$S6ZC0JB7MBKD34LTAGJ%4JI$46S4:-KJC3HC3183N:2I$4J%59/9+T53ZM$96PZ6+Q6X46E/9M.5+NN4A7XHMDYPWGO%42E8QFW6DX7 N6HK8+GO5D6L*O/HQB+P *PUHPM+Q3IRL*O-+RWGO-*OWGOQ+QNR2UMO+00ZS2C9EH9WQ5QRYA/BWSZ8CBO77CT77WQL 2O/VC9N37/PKRBIVAU82NKLL5MZWQ X5V1OV6IWLE%:6CB7G%9JPFHMVDTFVFD8NEZLHIAVAA0JY7U5", keyId: "8TRqlBQxUbQ", encodedSigningCert: "MIIBIzCByqADAgECAgQbc6tlMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBUVDLU1lMB4XDTIxMDQyMDA3Mjg1MVoXDTIxMDUyMDA3Mjg1MVowEDEOMAwGA1UEAwwFRUMtTWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASAnF9trnoiLJxV8zkWDCv4jM9/ls3bC5vVt/+oXkgHCOndb7e/7stg1OP64Gh3l/k64MlTBdR448bQA1IPXgOcoxIwEDAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSAAwRQIgcRqHvybuL5WlAlNusu++a+cR1onTcj9VeH9ymNsFnQUCIQDfs95vijEGiXZEz2D8LF2umf1zBHvTo2s9u8EW92NypA=="),
            new TestData(encodedEhnCert: "HC1:NCFOXNYTS3DHNXSO9WCVM86L+UQ*W5U 2HJ6ELBXG4KT266WTSJHK86%392PK7PAN9I6T/ZHBMIXLH7G3JRHRTI+*47ALF.KZ/KD-4$XKC%C%Q6NK9S P.Q6D%68%EDNEWW66G6.Q53C1B69GYPWRU1W5DB9.G9/G9VY95CQ-8EDS9%PP%.PZY9AKPCPP0%MS%MQW6%PQ5G6G%5 T9EKB%ZJRMI784W1J.ZJYIJ*8B.IJB8L+ZJY1BXZIG42$IJH7J*CL7TC TAKBI/8D:8DOVD7KDP9CJYJBKBQWT.+S1QDC8CO8CG8C3AD-ZJ9KB/VSQOL9DLKWCZ3EBKD.GILYJ7GPWZJZEBMEDTJCJKDLEDL9C.ZJU0C**UCKEJ/F%3M5II$2MSIJAUJX2M1GG8KE6JCW/I$DQ$CICO1BMIHSU1CJF4TZ-493IJ9GZSPL409FA5QNG+8X:802J9%IYQTHFTEP4N*KO1703L7:4A1LFBL$23V0H423JKB$IJY73%IJLD3:L3.43ERJ.43EAJ.43MOJ.F0D10/BQ 558JIH6M5DST.CU.VLB5ACCDWJ:VTYUM83L7TJM0PAZU*2WWQH$N1Z 7%:B6OC8WVN7N::UTXOUDOU%D8*7B$N6ENZQO6:4*Y5I5WI4NF GNP70LMD2RDN7L RAB2RWL NUE6P261GJ0LTT48S8+L$O676BFZV87MN6CRASSK12814TA5BJH%V3LT/VLOXQ7:8A1I%1J3AKWRG OGP UC/EU6IGO9VZFEMB VUC$9%:ONX3225*O50MNN SKMM/53E7MVI6YCSAKU+JUNI5DHRVQCYI7+B5L%V/M5X I+J8P1KX*IBUJORFND84UQ3AL+ 72$OB6G/7V2ED/NB7NVP7LEXUSTHOXG6OS-XV.QVLTH2WA XFR539-MFAESX2N9PD6OY$GZ$K16VETBUEF%FA$IDV00B7OV1", keyId: "wW_ZzXHLaWY", encodedSigningCert: "MIICszCCAZugAwIBAgIFAL2D8WQwDQYJKoZIhvcNAQELBQAwETEPMA0GA1UEAwwGUlNBLU1lMB4XDTIxMDQyMDA3Mjg1MloXDTIxMDUyMDA3Mjg1MlowETEPMA0GA1UEAwwGUlNBLU1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1M3pnkGw2SQTR+9scMOmCzoZo/lxnfTITYcvThNeO/iqBuvuq/m17B8laA7tWej2OGllkcyUEajiHm7t5JnDjE+bYyQaxzAJ2uLq+6E29/H7uqVnF9iQFLGqZBHkxXFAKnN4HXmbH3wZKBrY+JPWgMFtC4rHXmaWmBqOKBYz6VVYb68s1OO3t3CjliLiLZKVOOFOKUcXiXNoV16lP5QV+O8PWAFwH18+BZxp0sCfTblobVdRARHKdXstQZfp348q3YeCbbvntgCL0xn/XF9cZeeneHhTl4vD2IBrpjVjLEAZ+2rusR2PSg4UEM9UDhprV2+Tl5wC5gPd/iqv3j0+QIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQADggEBAH7Es0hJVNE7s6Fe7A9MgkXY1cvmkqaddCSTXeuRCq8GHXzPhAXzRcPkOvtkGRUxbCQznkMbUUGbHdpNA/LOAXhyVznPjffSpy+MxBttpx706dyovkS7NANpwk6MEr/oRjQGaDdvmH1wNtza1lbk451JZh2y17mV/kkxw4TH7IwNOSNgi5pGgwkMsVDViQAh4Uwcxih4SDAi9kmmaL65hDu7mEyPblVSdp7VjgwshBa1ybd0l6ezWqNibcGBG5JHjb2mkj31ZEL0n4VTyUd8BeKLjDi6tifibuWnsw2pxd6n+I1oPuJBJK+DGeIVsYEcjwKse3gaJpJ1ksS/Ic/OY7s="),
            new TestData(encodedEhnCert: "HC1:NCFI.L/8OAP29S2QINV25:T5M-BT8B*ZONTJDO6/UM5K5OHNNDUSB94%SJ$SJ%OEORLXC 1WO8UO 3SE4%KMM-MBZM7T6CKGI31TOPR4VYXD4CWVHHV21J-MTBHZ-E1QO:7SJ%V11GJCU*FRLEF2XQPAB/CNWEP:BSEZ2S*C9MTV%GNHFFBE:NEF7RR+N8TDA-RGLM5+K2NVR6QO HWUDNRRNPA:49S51B39Y:UEYAKLURNJT:5AQ8JNN0M21FH+1OHI4Q-21/QAMT0SEXBFCUNJ$CMDMHVISTTMEDESA6T0PNAF0QW/4INR$FGO*5QTK1SK-J8O.MG00X%3DDA1IKFM8KO1FT8.TGEU9+-2I-MYM0D$2NT8 H558J/LHPFJ7HM89R $64$1H-MG40 Z7C:G5SL7LOA0CCPO*%EPJE+M4NTCC93ZR85B2 :KECAGV1NDEB2D1DF84C:QPZOAP1IS621C8QFJ:BWP%A3GE9EL2LPVI6L$58JJ2+SDC2 *8WEQB:T.83N2WUS8O-FKKPT88:1K5KI812TAEH6CKVD46NLXRSGOQC4S+B1IM8O3H8OLVD*WDQW3$01EL7TPD.%6RZN:JBIQKYKBX5O-1WDEUV-JHFVOALV4CPOT$RBW%7C.J.MNZ-F- UNKNRSRGL56Y73ZF7AKAH6-9V9NO7JP*7T18S/+8NQV6ACHBE0SRW07JXVHY68$Q", keyId: "mgJOa1m_Qs4", encodedSigningCert: "MIIBJDCBy6ADAgECAgUA0+PgpTAKBggqhkjOPQQDAjAQMQ4wDAYDVQQDDAVFQy1NZTAeFw0yMTA0MTkxMjE3MjZaFw0yMTA1MTkxMjE3MjZaMBAxDjAMBgNVBAMMBUVDLU1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENB9s11TMwMOV+a9R+cf5RYFzKxI/sYW7dL6Fl+1ZkXTdQjXx02r06ktxdVpHEO4x2rCKrylSVfrQYhS86Y2/wqMSMBAwDgYDVR0PAQH/BAQDAgWgMAoGCCqGSM49BAMCA0gAMEUCIEgCjXr/MDspRyEoQB+XKblF04aWmenffKwy/hHD/x6GAiEAzsGgImW/bh1CVN867if7GKYVqNAM6Pxaumgf+3rhv3A=", shouldFale: true),
 */       };

        [TestMethod]
        public void TestData_SmokeTest()
        {
            var secrataryService = new SecretariatService();

            X509CertificateParser parser = new X509CertificateParser();
            foreach (var cert in testData.GroupBy(p => p.keyId))
            {
                var certBytes = Convert.FromBase64String(cert.First().encodedSigningCert);

                var x509certificate = parser.ReadCertificate(certBytes);
                secrataryService.AddPublicKey(cert.Key, x509certificate.GetPublicKey());
            }

            var decoder = new GreenCertificateDecoder();
            foreach (var cert in testData)
            {
                var dgc = decoder.Decode(cert.encodedEhnCert);
            }
        }

        [TestMethod]
        public void DecodeTest_VaccinationRSAKey()
        {
            string coseBase45 = "HC1:NCFO609G0/3WUWGVLKG79O20$RFUH4W 5H479CK0603XK2F3XJIHBM2F3X4ICBM/IC6TAY50.FK6ZK7:EDOLFVC*70B$D% D3IA4W5646946846.966KCN9E%961A69L6QW6B46XJCCWENF6OF63W5KF60A6WJCT3ETB8WJC0FDGE3STA IBN1BKCB2C9*H997B8DBAH88-AJ1B0M6R1AQ$D.UDRYA 96NF6L/5SW6Y57+EDB.DSY9/NAHM9HC8 QE*KE0ECKQEPD09WEQDD+Q6TW6FA7C46TPCBEC8ZKW.CNWE.Y92OAGY82+8UB8-R7/0A1OA1C9K09UIAW.CE$E7%E7WE KEVKER EB39W4N*6K3/D5$CMPCG/DA8DBB85IAAY8WY8I3DA8D0EC*KE: CZ CO/EZKEZ96446C56GVC*JC1A6NA73W5KF6TF6FBB*20*OAZG0:CLAD2BU0SINW0FK5SKW82SJ.Q5+.5$TFLVT5BMC76UWM1PUC771J54K5NPM3.84KP9 LP2Q/MJFQ48KE*AR/F7 5AKD7R.VG8HC/8TXGE/M%+CI.6D5NKYAQON0EN87R6.6$DIRRK EV-OJ0F4ZUA7ZB-+7S-CMHLTF5FDRZMC/86OY5C8OZ+MNJR 0IMO93N6QM7NO4*7MADFHWFAW4P12P*OM6AEDTZ0QOZ4*S456A8CGOLIX2AQWOW15MX5QWS 5IYX98HVUSDG13DY11PG9DQL:TN:V3%72%8FK2NAU069BB3RW2A4AFTABKFGUTK%D6BQACU3T5K4S*BU.ROSANRJ96ED4KN* 4:4I9PA0-5LYVHYMRCLXID7GM00";

            var decoder = new GreenCertificateDecoder();

            var cwt = decoder.Decode(coseBase45);

            Assert.IsNotNull(cwt);
            Assert.IsNotNull(cwt.DGCv1.Vaccination);
            Assert.AreEqual(cwt.CoseMessage.RegisteredAlgorithm, HCertSupportedAlgorithm.PS256);
        }

        [TestMethod]
        public void DecodeTest_VaccinationRSA3072Key()
        {
            string coseBase45 = "HC1:NCFH90GD0/3WUWGVLK.69%ET1F9F3J +DH479CK0603XK2F3XJI OQ2F3X4IVOQ/IC6TAY50.FK6ZK7:EDOLFVC*70B$D% D3IA4W5646946846.966KCN9E%961A69L6QW6B46XJCCWENF6OF63W5KF60A6WJCT3ETB8WJC0FDGE3STA IBN1BKCB2C9*H997B8DBAH88-AJ1B0M6R1AQ$D.UDRYA 96NF6L/5SW6Y57+EDB.DSY9/NAHM9HC8 QE*KE0ECKQEPD09WEQDD+Q6TW6FA7C46TPCBEC8ZKW.CNWE.Y92OAGY82+8UB8-R7/0A1OA1C9K09UIAW.CE$E7%E7WE KEVKER EB39W4N*6K3/D5$CMPCG/DA8DBB85IAAY8WY8I3DA8D0EC*KE: CZ CO/EZKEZ96446C56GVC*JC1A6NA73W5KF6TF6FBBCAGTZKR/QN+M5IPF26/UUQ1F8IUEVOHGKT:RS2HRKJB23QJ8%V66*BRQG4K5-N36VVE32M:NCOTZF7UJ136R9ZF897QMMR184J8IER93VG+7BWEH%31W9JXI*H9PUPRMJ-WIGRV+8WX9V3AW9KCPHL.NES-1+IS9KBMQ3* DSWG:%I$9I/MB2GW.YH+RC6+DV5C.P0TCG$XVYFJ8ON2:VKZFZNRAQRT4D-/65NLQ08QP8%51:AG.C6TV4G*6WYGQ76GL64LMJ5DANM+P5EC2EGHUTHJ2SDBR.%NZK090PP9OM4WESO:GCUI3V7BAOP%BF.WDF42PK8+3IRUR3%7 OCJ.2OCGF6E.%IVHT8AMV$4+09*.VL$JFG9.R3VJG5*NV6N.M6*V9./K76QJFCZ07N4I$-70LQF5J*H02F0L%2UNSV.0X3AM B*10T/EDH8H138TDAZHIX9MZT 5IKMN9*GQ5FQ0DB6806TZ4SM81/TR20KJ8WNAU5M94W6Y3K1*5TAANQC79H$BDBHFS2F*HLB RKYLPU4B*O4FK .5S6F+4PESVZIT%*3XVI9RDUIGGSEL9SD0";

            var decoder = new GreenCertificateDecoder();

            var cwt = decoder.Decode(coseBase45);

            Assert.IsNotNull(cwt);
            Assert.IsNotNull(cwt.DGCv1.Vaccination);
            Assert.AreEqual(cwt.CoseMessage.RegisteredAlgorithm, HCertSupportedAlgorithm.PS256);
        }

        [TestMethod]
        public void DecodeTest_Vaccination_FaultyCbor()
        {
            string coseBase45 = "HC1:NCFY/L 1A+J2+N2:8EWQTEDHZIB8HPB2N:05XEV:%NI*PMHDQ-3J-OGB9LENGTE+.KXDI6ZM.2EBYB1*D8CKZPNWM45HR:I3/D1+S0.*R9*GU7MQHOY6CSHE3YAW0SV.O*$JMVNF6OM/DGXSXYOH6EO06:M1Z2E4*GL.JFBR-Q3/4HJ/GADLHTJ$FN/100PD7ZGUL50EKT243S3HG79*9V89.OG5ZG%QS6J1QKOE+U9YBDGHQ FOXE%4S-/IA+IML2XT0*Q7WA9IQ6MNI%IBQRT%PIODH+K9$MMM.4%2P5/1RCS79GIJEST7UVFLRS+9LTPE8FRSBGD3FOX7N+ULDPZS0Z$QN6G%$AFD1PS0FEFCL60DF3CELF85EMR7AXOL:J1TICD:O1U6OZJ6GW8LQ 1IUWB44WLS18U8 DTRSRDV0TT5+MOE2UTXC2GI5I7 J9VG4PCLMQB 55KY4T151PK/QNSNMM$KBPLRBW+VGOFLBZK/4KD1P%RI6WPG5QH79KENSUA.GEAV6V.UC TJSGGAL8VH11W.:S0QTZ6I2/A8 UGAWD$UCENV/VHZE49D05T IF.PU7TFTETAXM2:VNGD2MV:K5AWM";

            var decoder = new GreenCertificateDecoder();
            try
            {
                var cwt = decoder.Decode(coseBase45);
                Assert.Fail();
            }
            catch (InvalidOperationException)
            {
                return;
            }
        }
    }
}
