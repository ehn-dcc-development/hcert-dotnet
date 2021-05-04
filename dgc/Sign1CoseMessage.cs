using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace DGC
{
    public class Sign1CoseMessage
    {
        const int Sign1Tag = 18;
        private const string ContextSignature1 = "Signature1";
        static readonly CBORObject HeaderKey_Alg = CBORObject.FromObject(1);
        static readonly CBORObject Alg_ES256 = CBORObject.FromObject(-7);
        static readonly CBORObject Alg_PS256 = CBORObject.FromObject(-37);
        static readonly CBORObject HeaderKey_KID = CBORObject.FromObject(4);

        public byte[] Content { get; set; }
        public byte[] Signature { get; set; }
        public HCertSupportedAlgorithm RegisteredAlgorithm { get; private set; }
        public string KID { get; private set; }
        public CBORObject ProtectedMap { get; private set; }

        public static Sign1CoseMessage DecodeFromBytes(byte[] coseBytes)
        { 
            var cborMsg = CBORObject.DecodeFromBytes(coseBytes);

            if (cborMsg.Type != CBORType.Array) throw new InvalidDataException("Message is not a COSE security message.");
            if (cborMsg.MostOuterTag.ToInt32Checked() != Sign1Tag) throw new InvalidDataException("Message is not a COSE security message.");
            if (cborMsg.Count != 4) throw new InvalidDataException("Invalid Sign1 structure");

            var protectedBytes = cborMsg[0].GetByteString();
            var protectedMap = CBORObject.DecodeFromBytes(protectedBytes);
            
            var unprotectedMap = cborMsg[1];

            var coseMsg = new Sign1CoseMessage();
            coseMsg.Content = cborMsg[2].GetByteString();
            coseMsg.Signature = cborMsg[3].GetByteString();
            coseMsg.ProtectedMap = protectedMap;

            var algKey = protectedMap[HeaderKey_Alg];
            if (algKey.AsInt32() == Alg_ES256.AsInt32())
            {
                coseMsg.RegisteredAlgorithm = HCertSupportedAlgorithm.ES256;
            }
            else if (algKey.AsInt32() == Alg_PS256.AsInt32())
            {
                coseMsg.RegisteredAlgorithm = HCertSupportedAlgorithm.PS256;
            }
            else
            {
                throw new NotSupportedException("Algorithm not supported");
            }

            if (unprotectedMap[HeaderKey_KID] != null)
            {
                var kidBytes = unprotectedMap[HeaderKey_KID].GetByteString();
                coseMsg.KID = Convert.ToBase64String(kidBytes);
            }
            else
            {
                var kidBytes = protectedMap[HeaderKey_KID].GetByteString();
                coseMsg.KID = Convert.ToBase64String(kidBytes);
            }
            return coseMsg;
        }

        public byte[] EncodeToBytes()
        {
            var coseObj = CBORObject.NewArray();

            var protectedMap = CBORObject.NewMap();
            if (RegisteredAlgorithm == HCertSupportedAlgorithm.ES256)
            {
                protectedMap[HeaderKey_Alg] = Alg_ES256;
            }
            else if (RegisteredAlgorithm == HCertSupportedAlgorithm.PS256)
            {
                protectedMap[HeaderKey_Alg] = Alg_PS256;
            }

            coseObj.Add(protectedMap.EncodeToBytes());

            var unProtectedMap = CBORObject.NewMap();
            var kidBytes = Convert.FromBase64String(KID);
            unProtectedMap[HeaderKey_KID] = CBORObject.FromObject(kidBytes);
            coseObj.Add(unProtectedMap);

            coseObj.Add(CBORObject.FromObjectAndTag(Content, 2));
            coseObj.Add(CBORObject.FromObjectAndTag(Signature, 3));
            return CBORObject.FromObjectAndTag(coseObj, Sign1Tag).EncodeToBytes();
        }

        public void Sign(AsymmetricCipherKeyPair keypair, HCertSupportedAlgorithm alg, string keyid)
        {
            ISigner signer;
            var signLenght = 0;
            var protectedMap = CBORObject.NewMap();
            if (alg == HCertSupportedAlgorithm.ES256)
            {
                RegisteredAlgorithm = HCertSupportedAlgorithm.ES256;
                protectedMap[HeaderKey_Alg] = Alg_ES256;
                signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signLenght = 32;
            }
            else if (alg == HCertSupportedAlgorithm.PS256)
            {
                RegisteredAlgorithm = HCertSupportedAlgorithm.PS256;
                protectedMap[HeaderKey_Alg] = Alg_PS256;

                signer = SignerUtilities.GetSigner("SHA256withRSA/PSS");
            }
            else
            {
                throw new NotSupportedException("Algorithm not supported");
            }

            signer.Init(true, keypair.Private);
            var cborArray = CBORObject.NewArray();
            cborArray.Add(ContextSignature1);
            cborArray.Add(protectedMap.EncodeToBytes());
            cborArray.Add(new byte[0]);
            cborArray.Add(Content);

            var bytesToSign = cborArray.EncodeToBytes();
            signer.BlockUpdate(bytesToSign, 0, bytesToSign.Length);

            var signature = signer.GenerateSignature();
            if (signLenght > 0)
            {
                signature = ConvertDerToConcat(signature, signLenght);
            }

            Signature = signature;

            KID = keyid;
        }

        public bool VerifySignature(AsymmetricKeyParameter pubKey)
        {
            ISigner signer;
            var signature = Signature;
            if (pubKey is Org.BouncyCastle.Crypto.Parameters.ECKeyParameters)
            {
                signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signature = ConvertConcatToDer(Signature);
            }
            else if (pubKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)
            {
                signer = SignerUtilities.GetSigner("SHA256withRSA/PSS");
            }
            else
            {
                throw new ArgumentException("Algorithm not supported");
            }
 
            signer.Init(false, pubKey);
            
            var cborArray = CBORObject.NewArray();
            cborArray.Add(ContextSignature1);
            cborArray.Add(ProtectedMap.EncodeToBytes());
            cborArray.Add(new byte[0]); // no externaldata
            cborArray.Add(Content);

            var bytesToSign = cborArray.EncodeToBytes();
            // if ec then encode
            signer.BlockUpdate(bytesToSign, 0, bytesToSign.Length);

            return signer.VerifySignature(signature);
        }

        private static byte[] ConvertConcatToDer(byte[] concat)
        {
            int len = concat.Length / 2;

            byte[] r = new byte[len];
            Array.Copy(concat, 0, r, 0, len);
            r = UnsignedInteger(r);

            byte[] s = new byte[len];
            Array.Copy(concat, len, s, 0, len);
            s = UnsignedInteger(s);

            var x = new List<byte[]>();
            x.Add(new byte[] { 0x30 });
            x.Add(new byte[] { (byte)(r.Length+s.Length) });
            x.Add(r);
            x.Add(s);

            var der = x.SelectMany(p => p).ToArray();
            return der;
        }

        private static byte[] UnsignedInteger(byte[] i)
        {
            int pad = 0, offset = 0;

            while (offset < i.Length && i[offset] == 0)
            {
                offset++;
            }

            if (offset == i.Length)
            {
                return new byte[] { 0x02, 0x01, 0x00 };
            }
            if ((i[offset] & 0x80) != 0)
            {
                pad++;
            }

            int length = i.Length - offset;
            byte[] der = new byte[2 + length + pad];
            der[0] = 0x02;
            der[1] = (byte)(length + pad);
            Array.Copy(i, offset, der, 2 + pad, length);

            return der;
        }

        private static byte[] ConvertDerToConcat(byte[] der, int len)
        {
            // this is far too naive
            byte[] concat = new byte[len * 2];

            // assumes SEQUENCE is organized as "R + S"
            int kLen = 4;
            if (der[0] != 0x30)
            {
                throw new Exception("Unexpected signature input");
            }
            if ((der[1] & 0x80) != 0)
            {
                // offset actually 4 + (7-bits of byte 1)
                kLen = 4 + (der[1] & 0x7f);
            }

            // calculate start/end of R
            int rOff = kLen;
            int rLen = der[rOff - 1];
            int rPad = 0;
            if (rLen > len)
            {
                rOff += (rLen - len);
                rLen = len;
            }
            else
            {
                rPad = (len - rLen);
            }
            // copy R
            Array.Copy(der, rOff, concat, rPad, rLen);

            // calculate start/end of S
            int sOff = rOff + rLen + 2;
            int sLen = der[sOff - 1];
            int sPad = 0;
            if (sLen > len)
            {
                sOff += (sLen - len);
                sLen = len;
            }
            else
            {
                sPad = (len - sLen);
            }
            // copy S
            Array.Copy(der, sOff, concat, len + sPad, sLen);

            return concat;
        }
    }
}