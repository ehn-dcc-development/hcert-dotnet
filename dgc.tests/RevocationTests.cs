﻿using DCC;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace DGC.Tests
{
    [TestClass]
    public class RevocationTests
    {
        [TestMethod]
        public void ComputeSignatureHash_EC_Success()
        {
            var decert = "HC1:6BFOXN*TS0BI$ZDYSHTRMM7QXSUJCQF*8OJENDC2LE $CSK9TXTA4DGL9.*HB0E/GPWBILC9GGBYPLR-SNF10EQ928GEQW2DVJ5UL8W2BM8QZ.256CQ01.N85VO-2GD:6-646KQYI65SO4UODEQ1EP1IQSS9L35/97*8D6IA*$36IASD9YHI5IIX2M KM1GGYIALEE-7A%IA%DA9MGF:F81H23DLEE+-C/DD.IAHLCV5GVWN.FKP12SLJ/LJB/S7-SN2H N37J3JFTULJBGJ8X2-36D-I/2DBAJDAJCNB-43 X4VV2 73-E3ND3DAJ-43+*4.$SO90$96%409707LPMIH-O92UQ*SQ H2UKAPN1.UIAYUMMO3-SY$N/UEE09+-214AM.SY$N.SAYO7FT5D75W9AAABG64MC4SPSO 5DDVBH72/TDY5SZFF5PND7XV5/9HX%Q+ZQ%ABU2JS4MFHBR1D-572SKIQRZED+SIV+I2/B8*UEFUR/P+AR0EJM-FY0P+RK.90G.M84";

            var decode = new DCC.GreenCertificateDecoder();
            var cwt = decode.Decode(decert);

            var signatureHash = RevocationUtils.ComputeSignatureHash(cwt);
            
            Assert.AreEqual("s7QddDF+SZ6oSMRNeCss+Q==", Convert.ToBase64String(signatureHash));
        }

        [TestMethod]
        public void ComputeUCIHash__Success()
        {
            var decert = "HC1:NCFOXN%TSMAHN-HKTGX94G-ICWEXWP769W1O3XH74M6R5-F9.C7AVDLF9$BVPV5-FJLF6CB9YPD.+IKYJ1A4DBCEF3JTC 5T8MS*XC9NDF0D*JC10067T$2JE%50OPG989B9+HF9B9LW4G%8Z*8CNNO5P3*8VD9H:OD4OYGFO-O/HL.KJ C1TGL0LOYGFDB5*95MKN4NN3F85QN$24:O1$R1 SI5K1*TB3:U-1VVS1UU1$%HFTIPPA-RI PQVW5/O16%HAT1Z%PHOP+MMBT16Y5+Z9XV7G+SI*VQBKCY0CNNX/GJZII7JSTNB95R/5/35-17U451MOJ/U07PYPLC.UDXD1TQKQ7MDT3PKS/V3-SY$N8XJR4G$8R43GIAS348 FLC.U:MIF7ME09+K3 7P124HJSFRMLNKNM8POCJPGP6HEJ6%*N+$8LON.ONMWT2ETCO2POMIFE606843B*THHET9TZTH7OJ X2V5DI4W.O60DR2PN$0T03US:TAU3H7J1VB2:C3OBT170AT040:EO%0";

            var decode = new DCC.GreenCertificateDecoder();
            var cwt = decode.Decode(decert);

            var signatureHash = RevocationUtils.ComputeUCIHash(cwt);

            Assert.AreEqual("P4nd4fPW4wjQOqv8VWdxBw==", Convert.ToBase64String(signatureHash));
        }
    }
}