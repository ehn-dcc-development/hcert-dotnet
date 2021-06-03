using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DGC
{
    public class Sign1CoseMessage
    {
        const int Sign1Tag = 18;
        const int CoseHeader_ProtectedMap = 0;
        const int CoseHeader_UnProtectedMap = 1;
        const int CoseHeader_Content = 2;
        const int CoseHeader_Signature = 3;

        private const string ContextSignature1 = "Signature1";
        private const int DerSequenceTag = 0x30;

        static readonly CBORObject HeaderKey_Alg = CBORObject.FromObject(1);
        static readonly CBORObject Alg_ES256 = CBORObject.FromObject(-7);
        static readonly CBORObject Alg_PS256 = CBORObject.FromObject(-37);
        static readonly CBORObject HeaderKey_KID = CBORObject.FromObject(4);

        public byte[] Content { get; set; }
        public byte[] Signature { get; set; }
        public DGCertSupportedAlgorithm RegisteredAlgorithm { get; private set; }
        public string KID { get; private set; }
        public byte[] ProtectedBytes { get; set; }

        public static Sign1CoseMessage DecodeFromBytes(byte[] coseBytes)
        { 
            var cborMsg = CBORObject.DecodeFromBytes(coseBytes);

            if (cborMsg.Type != CBORType.Array) throw new InvalidDataException("Message is not a COSE security message.");
            if (cborMsg.Count != 4) throw new InvalidDataException("Invalid Sign1 structure");

            var protectedBytes = cborMsg[CoseHeader_ProtectedMap].GetByteString();
            var protectedMap = CBORObject.DecodeFromBytes(protectedBytes);
            
            var unprotectedMap = cborMsg[CoseHeader_UnProtectedMap];

            var coseMsg = new Sign1CoseMessage();
            coseMsg.Content = cborMsg[CoseHeader_Content].GetByteString();
            coseMsg.Signature = cborMsg[CoseHeader_Signature].GetByteString();
            coseMsg.ProtectedBytes = protectedBytes;

            var algKey = protectedMap[HeaderKey_Alg];
            if (algKey.AsInt32() == Alg_ES256.AsInt32())
            {
                coseMsg.RegisteredAlgorithm = DGCertSupportedAlgorithm.ES256;
            }
            else if (algKey.AsInt32() == Alg_PS256.AsInt32())
            {
                coseMsg.RegisteredAlgorithm = DGCertSupportedAlgorithm.PS256;
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
            if (RegisteredAlgorithm == DGCertSupportedAlgorithm.ES256)
            {
                protectedMap[HeaderKey_Alg] = Alg_ES256;
            }
            else if (RegisteredAlgorithm == DGCertSupportedAlgorithm.PS256)
            {
                protectedMap[HeaderKey_Alg] = Alg_PS256;
            }

            var kidBytes = Convert.FromBase64String(KID);
            protectedMap[HeaderKey_KID] = CBORObject.FromObject(kidBytes);

            coseObj.Add(protectedMap.EncodeToBytes());
            
            var unProtectedMap = CBORObject.NewMap();
            coseObj.Add(unProtectedMap);

            coseObj.Add(Content);
            coseObj.Add(Signature);

            return CBORObject.FromObjectAndTag(coseObj, Sign1Tag).EncodeToBytes();
        }

        public void Sign(AsymmetricCipherKeyPair keypair, DGCertSupportedAlgorithm alg, string keyid)
        {
            ISigner signer;
            var signLength = 0;
            var protectedMap = CBORObject.NewMap();
            if (alg == DGCertSupportedAlgorithm.ES256)
            {
                RegisteredAlgorithm = DGCertSupportedAlgorithm.ES256;
                protectedMap[HeaderKey_Alg] = Alg_ES256;
                signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signLength = 32;
            }
            else if (alg == DGCertSupportedAlgorithm.PS256)
            {
                RegisteredAlgorithm = DGCertSupportedAlgorithm.PS256;
                protectedMap[HeaderKey_Alg] = Alg_PS256;

                signer = SignerUtilities.GetSigner("SHA256withRSA/PSS");
            }
            else
            {
                throw new NotSupportedException("Algorithm not supported");
            }
            var kidBytes = Convert.FromBase64String(keyid);
            protectedMap[HeaderKey_KID] = CBORObject.FromObject(kidBytes);

            signer.Init(true, keypair.Private);
            var cborArray = CBORObject.NewArray();
            cborArray.Add(ContextSignature1);
            cborArray.Add(protectedMap.EncodeToBytes());
            cborArray.Add(new byte[0]);
            cborArray.Add(Content);

            var bytesToSign = cborArray.EncodeToBytes();
            signer.BlockUpdate(bytesToSign, 0, bytesToSign.Length);

            var signature = signer.GenerateSignature();
            if (signLength > 0)
            {
                signature = ConvertDerToConcat(signature, signLength);
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
            cborArray.Add(ProtectedBytes);
            cborArray.Add(new byte[0]); // no externaldata
            cborArray.Add(Content);

            var bytesToSign = cborArray.EncodeToBytes();
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
            x.Add(new byte[] { DerSequenceTag });
            x.Add(new byte[] { (byte)(r.Length+s.Length) });
            x.Add(r);
            x.Add(s);

            var der = x.SelectMany(p => p).ToArray();
            return der;
        }

        private static byte[] UnsignedInteger(byte[] i)
        {
            var offset = Array.FindIndex(i, elem => elem != 0);

            if (offset == -1)
            {
                // Is 0
                return new byte[] { 0x02, 0x01, 0x00 };
            }

            int pad = (i[offset] & 0x80) != 0 ? 1 : 0;

            int length = i.Length - offset;
            byte[] der = new byte[2 + length + pad];
            der[0] = 0x02;
            der[1] = (byte)(length + pad);
            Array.Copy(i, offset, der, 2 + pad, length);

            return der;
        }

        private static byte[] ConvertDerToConcat(byte[] der, int len)
        {
            if (der[0] != DerSequenceTag)
            {
                throw new Exception("Unexpected signature input");
            }

            byte[] concat = new byte[len * 2];

            // assumes SEQUENCE is organized as "R + S"
            // calculate start/end of R
            int rOffset = 4; // first few bytes containing der structure info
            int rLen = der[3];
            int rPad = 0;
            if (rLen > len)
            {
                rOffset += (rLen - len);
                rLen = len;
            }
            else
            {
                rPad = (len - rLen);
            }
            // copy R
            Array.Copy(der, rOffset, concat, rPad, rLen);

            // calculate start/end of S
            int sOff = rOffset + rLen + 2;
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
