using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DCC
{
    public class Sign1CoseMessage
    {
        const int Sign1Tag = 18;
        const int CoseHeader_ProtectedMap = 0;
        const int CoseHeader_UnProtectedMap = 1;
        const int CoseHeader_Content = 2;
        const int CoseHeader_Signature = 3;

        private const string ContextSignature1 = "Signature1";

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

        public void Sign(AsymmetricAlgorithm key, string keyid)
        {
            var protectedMap = CBORObject.NewMap();

            if (key is ECDsa)
            {
                RegisteredAlgorithm = DGCertSupportedAlgorithm.ES256;
                protectedMap[HeaderKey_Alg] = Alg_ES256;

            }
            else if (key is RSA)
            {
                RegisteredAlgorithm = DGCertSupportedAlgorithm.PS256;
                protectedMap[HeaderKey_Alg] = Alg_PS256;
            }
            else
            {
                throw new NotSupportedException("Algorithm not supported");
            }

            var kidBytes = Convert.FromBase64String(keyid);
            protectedMap[HeaderKey_KID] = CBORObject.FromObject(kidBytes);

            var cborArray = CBORObject.NewArray();
            cborArray.Add(ContextSignature1);
            cborArray.Add(protectedMap.EncodeToBytes());
            cborArray.Add(new byte[0]);
            cborArray.Add(Content);

            var bytesToSign = cborArray.EncodeToBytes();

            byte[] signature;
            if (key is ECDsa)
            {
                signature = (key as ECDsa).SignData(bytesToSign, HashAlgorithmName.SHA256);
            }
            else if (key is RSA)
            {
                signature = (key as RSA).SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }
            else
            {
                throw new NotSupportedException("Algorithm not supported");
            }

            Signature = signature;

            KID = keyid;
        }

        public bool VerifySignature(X509Certificate2 cert)
        {
            var signature = Signature;
 
            var cborArray = CBORObject.NewArray();
            cborArray.Add(ContextSignature1);
            cborArray.Add(ProtectedBytes);
            cborArray.Add(new byte[0]); // no externaldata
            cborArray.Add(Content);

            var bytesToSign = cborArray.EncodeToBytes();

            var ecdakey = cert.GetECDsaPublicKey();
            if (ecdakey != null)
            {
                //signature = ConvertConcatToDer(Signature);
                return ecdakey.VerifyData(bytesToSign, signature, HashAlgorithmName.SHA256);
            }

            var rsaKey = cert.GetRSAPublicKey();
            if (rsaKey != null)
            {
                return rsaKey.VerifyData(bytesToSign, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }

            throw new Exception("Public key algorithm not supported");   
        }
    }
}
