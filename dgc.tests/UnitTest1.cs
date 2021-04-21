using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DGC.Tests
{
    [TestClass]
    public class UnitTest1
    {
        private static CWT CreateCWTTestData()
        {
            var tests = new List<Tst>
            {
                new Tst
                {
                    Dis = "Covid-19",
                }
            };

            var vacs = new List<Vac>
            {
                new Vac
                {   
                    Adm ="Test Org"
                }
            };

            CWT cwt = new CWT();
            cwt.DGCv1 = new EuHcertV1Schema
            {
                Sub = new Sub { Fn = "Test Testson" },
                Tst = tests.ToArray(),
                Vac = vacs.ToArray()
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

            var cwtToTest = CreateCWTTestData();
            string encoded = new GreenCertificateEncoder(keypair).Encode(cwtToTest);
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

            var cwtToTest = CreateCWTTestData();

            string encoded = new GreenCertificateEncoder(keypair).Encode(cwtToTest);
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

            var cwtToTest = CreateCWTTestData();
            string encoded = new GreenCertificateEncoder(keypair).Encode(cwtToTest);
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
            string coseBase45 = "HC1:NCFC:MU.NZVQH435EEW*LN83EGK3GH+SC937U0OXE7UGA692 7JWBALED%81R6M :TX2IEUR$25OBH%32560S79O6IOHGFH86WEINTL8CH0PEGK*H8:66ZOMD8CWJC-7GLHT6AFGQVY.UN.L$:3GG7V UOK7M+SD1V F60O548J6:4Q4EN2CLDM9OC.EM%0K$167VCFT9P$5MJAM5FAI1FB6EXBLGNTYMZVC%LHG63MMDT:B15CYN6YQQLG5$HNM2EDF1MIDL85-M2I2D8JSH9G9KFGQ2:AV*GH04686N2IIC-GFC9984TSJI%AHLBUKM3CK.VEN+FRAB7005FSUJER7B3%BA73J676 HN68+Z8EAM-5BEKK697WZI8%D/I8DHDXX0YM0L$34LIOI8OD2I7DITRB3HZI1S30M8A9%7+SJU75+RIOW97AOTL9A*8X0WCE6UM13ER56G.%O507DPE5/0NE5DUL$RGG77YD0R$L$CPB6IZAG6/HWDN02FO/RO741DFA55E*5J%5HTP28R9VI58S23U:.1B:8OK7S8ITCSL6FL2S3-JZ:NLZV4:N%270 F:-R65F%.A.LAFRFPYQ0Y7G+D12AU8M2:7Q6FC-V1*VZH6D3N";

            var decoder = new GreenCertificateDecoder();

            var cwt = decoder.Decode(coseBase45);

            Assert.IsNotNull(cwt);
            Assert.IsNotNull(cwt.DGCv1.Vac);
            Assert.AreEqual(cwt.RegisteredAlgorithm, HCertSupportedAlgorithm.ES256);
        }

        [TestMethod]
        public void DecodeTest_VaccinationRSAKey()
        {
            string coseBase45 = "HC1:NCFOXNYTS3DH$YO:CQSU40 H 804 2FI15B3LR5OGIXI97QM:X93IKTSKKQCAQCCV4*XUT3PDJPO-OJX1H:O/B9VLIYMAW-2H0D523UA30BJAG7LWT7J31$4OH0N*4-O4PN0Y/K5+C$/IU7J$%2DU28:I /KU%CW.4WV2L4L$XK5AL5:4A930JBIFTW63EG3%X4FV4X17WH9$V9H.L*714T9K6QTM90NPK9QF698.P+95XXAOVPX0QON9846-$03O5RF6$T61R6B46646ZY9EQ5-NP*.1D9R+Q6646C%6RF6S$92Y9DFPVX1R270:6NEQ0R6AOMJ%5AX54T9KJP-5Q746B46O1N646IN9/2QQW0F46515QT4.NRH998SOFHP$$9OGOF46JY4ET4$21WR1ZDAS*21 48W4HS69O2H/FZEFOQ3M9D/$SCPC.L8*EM-G27TQWS1VS1NQ1QRH*QIFIA.RQ:L6TI5AT1LV3LU9CO1-.PM-P:ZH8 9XVHLU9B$PHQ1+V93W1-V9AU9C+CK+J/HC-MPCFM$7O$YECRKSLN3GE8/64%2FIJH IOY5+/BJ7LN2WRV5VE15FV$SF897CMC.$B..PH7N.WNK8I6XN7D2BJA*/RQ.FP7GP*5KNLJ UDI4E6W*QV1:C9KUSQPA/6GTB9FNX94$3P:8JXPC+W9LUL35Q:RK1/CK7M1QVXCSOKDVRN KT49S.X7DTRY2E9PMGALI2KAOTT9VVM547QFSFZMS$WRDZN$77*9FR$VE1AOW1AP7I0QDCRJUB%3PPDBHTLMHI5GCTLM$EW0%HD8PE.K241X2232W5MG86P5Z5170YS3CPQ-F6IT8YZ6+GV.*T.NQYCERZT/YAF:1NZ3F%FC1FJ*H7$RCXTSTHNN2HVT-I7X-FA5LI7SH16P%D0ZOPUD*1830ONIVBOF+PO*3SP3HYM0R.M: 3";

            var decoder = new GreenCertificateDecoder();

            var cwt = decoder.Decode(coseBase45);

            Assert.IsNotNull(cwt);
            Assert.IsNotNull(cwt.DGCv1.Vac);
            Assert.AreEqual(cwt.RegisteredAlgorithm, HCertSupportedAlgorithm.PS256);
        }

        [TestMethod]
        public void DecodeTest_VaccinationRSA3072Key()
        {
            string coseBase45 = "HC1:NCFC:MDOBFOAC40DNUA*4K.A.*4Y$B+BBT*EAFUM6Q JRV.KCZOTZI4*K/+HKSEF/J7KIQ*PE2EIX2LHJ7VGDNG-ZITLLMH99A5V73/DCT+7WTS8$3ZIAT/1EMJ-NI+:MH.KT5S3GW-DT/ A0CBADJA+8LP3T:SJXI:03%3QY+U0F0PP0R%S$9A-E8YVOFD1*8KX85F3R/.DHIC6-972F5$3QI6QF3XIPPA2BHC+N7$85KA8IYV1:JDDB8LG7-5/BEVGH/O6UAF-5AP:2-NUKX9:-P9*61$GDFP8F7C241LM*ZH5W2AB6D$MU6M*FUZM9A0ASVLS%OYT9CQK4547RM0K5Q3UTH9:44QO3O13363UN73+C00K.B1E20+8GBQGCLC4A7A0B--QLBL$RG$ERM$3Y9CBWCMUE+GODO3WT5B.AL3C6/P6JCB-8RSQX35V$I820*K48J9+7GVH1:%EB7B4FOCL89*VD/I.*03KO:55WOG/07N/54*IBV24801M2FNAE$2JKP0 3RBK$19L64JF6468Z%0078QYMF9G%JB*43JMU.*VKX181BD BXAR-YUPIA0UND55AG7OMU4M1W/J8IIY I1EVEI46ZC :35-DZH1E35+$G V27PTX A1Q7J4LJXPUN9V5KR 8%.KT7S$XNH/P$AN6H6:S4WUI%%0$KV+9VLTSP$NO3KM9J4%C:-VU47*YS%IBMOL6J7LWVBULG.3*04C-Q/D9BSNXHL TNNUU*179AFELEZ2WIDA+JVELOQ:5I*5M:4+ARJAD4.RJFF/39FU9DPM*DA-M5LVLT4R%/6QIN13K/GG3:U1SIF8M0/LD3FUD1SOO9XNG8PF.60XAK0H68P1$DOZC08KB1OJ5NWMHPDL%Q656UJWUM6MUYAZQ024SDR8M636ZU7$VI619IVL.2LZHT*F2IN9CE$GV:LB/:J4W828L4RCD$1F0L%5K2O6ABMR9WG4V LU*X0WNVRNT03EK.T11RDCTF3N0LVRNRW8U+0Q.3KX:PGDJ36DSAPU.6$0Q1CR$O34SEOZ6 HS.KI-UQN336AFD-7F3D31J4MP1%U$IG4:JJQGSJIG1M2-N%ZQ+KOXAC4SPHM3O87BQM.TR4FJESO2ZFNH6D:QJ/7RJ1ABB";

            var decoder = new GreenCertificateDecoder();

            var cwt = decoder.Decode(coseBase45);

            Assert.IsNotNull(cwt);
            Assert.IsNotNull(cwt.DGCv1.Vac);
            Assert.AreEqual(cwt.RegisteredAlgorithm, HCertSupportedAlgorithm.PS256);
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
