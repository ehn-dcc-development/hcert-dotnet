using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PeterO.Cbor;
using System;
using System.IO;
using System.Text;

namespace DGC
{

    internal class Sign1CoseMessage
    {
        const int Sign1Tag = 18;
        static readonly CBORObject HeaderKey_Alg = CBORObject.FromObject(1);
        static readonly CBORObject Alg_ES256 = CBORObject.FromObject(-7);
        static readonly CBORObject Alg_PS256 = CBORObject.FromObject(-37);
        static readonly CBORObject HeaderKey_KID = CBORObject.FromObject(4);

        public byte[] Content { get; set; }
        public byte[] Signature { get; set; }
        public HCertSupportedAlgorithm RegisteredAlgorithm { get; private set; }
        public string KID { get; private set; }


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
                coseMsg.KID = Encoding.UTF8.GetString(kidBytes);
            }
            else
            {
                var kidBytes = protectedMap[HeaderKey_KID].GetByteString();
                coseMsg.KID = Encoding.UTF8.GetString(kidBytes);
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
            var kidBytes = Encoding.UTF8.GetBytes(KID);
            unProtectedMap[HeaderKey_KID] = CBORObject.FromObject(kidBytes);
            coseObj.Add(unProtectedMap);

            coseObj.Add(CBORObject.FromObjectAndTag(Content, 2));
            coseObj.Add(CBORObject.FromObjectAndTag(Signature, 3));
            return CBORObject.FromObjectAndTag(coseObj, Sign1Tag).EncodeToBytes();
        }

        public void Sign(AsymmetricCipherKeyPair keypair, HCertSupportedAlgorithm alg)
        {
            ISigner signer;
            if (alg == HCertSupportedAlgorithm.ES256)
            {
                RegisteredAlgorithm = HCertSupportedAlgorithm.ES256;

                signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            }
            else if (alg == HCertSupportedAlgorithm.PS256)
            {
                RegisteredAlgorithm = HCertSupportedAlgorithm.PS256;

                signer = SignerUtilities.GetSigner("SHA256withRSA/PSS");
            }
            else
            {
                throw new NotSupportedException("Algorithm not supported");
            }

            signer.Init(true, keypair.Private);
            signer.BlockUpdate(Content, 0, Content.Length);

            var signature = signer.GenerateSignature();
            Signature = signature;

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keypair.Public);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            KID = Convert.ToBase64String(serializedPublicBytes).Substring(0, 8);
        }
    }
}


