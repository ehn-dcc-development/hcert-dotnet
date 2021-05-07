using System.IO;
using ICSharpCode.SharpZipLib.Zip.Compression;
using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using NL.MinVWS.Encoding;
using Org.BouncyCastle.Crypto;

namespace DGC
{
    public class GreenCertificateEncoder
    {
        private readonly AsymmetricCipherKeyPair keypair;
        private readonly string _keyid;

        public GreenCertificateEncoder(AsymmetricCipherKeyPair keypair, string keyid)
        {
            this.keypair = keypair;
            _keyid = keyid;
        }

        public class EncodeIntermediateData
        {
            public byte[] CwtBytes { get; set; }
            public byte[] CoseBytes { get; set; }
            public byte[] CompressedBytes { get; set; }
            public string Base45String { get; set; }
        }

        public string Encode(CWT cwt)
        {
            var (prefix, _) = EncodeIntermediateDataReturn(cwt);
            return prefix;
        }

        public (string, EncodeIntermediateData) EncodeIntermediateDataReturn(CWT cwt)
        {
            var cwtBytes = cwt.EncodeToBytes();
            var coseBytes = GetCOSEBytes(cwtBytes);
            var commpressed = GetCompressedBytes(coseBytes);
            var base45 = GetBase45(commpressed);
            return ("HC1:" + base45, new EncodeIntermediateData
            {
                CwtBytes = cwtBytes,
                Base45String = base45,
                CompressedBytes = commpressed,
                CoseBytes = coseBytes
            });
        }

        private string GetBase45(byte[] deflateBytes)
        {
            return Base45Encoding.Encode(deflateBytes);
        }

        private byte[] GetCompressedBytes(byte[] buffer)
        {
            using (var inputStream = new MemoryStream(buffer))
            using (var outStream = new MemoryStream())
            using (var deflateStream = new DeflaterOutputStream(outStream, new Deflater(Deflater.BEST_COMPRESSION)))
            {
                inputStream.CopyTo(deflateStream);
                deflateStream.Finish();
                return outStream.ToArray();
            }
        }

        private byte[] GetCOSEBytes(byte[] cborBytes)
        {
            var msg = new Sign1CoseMessage();
            msg.Content = cborBytes;

            if (keypair.Private is Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)
            {
                msg.Sign(keypair, DGCertSupportedAlgorithm.PS256, _keyid);
            }
            else if (keypair.Private is Org.BouncyCastle.Crypto.Parameters.ECKeyParameters)
            {
                msg.Sign(keypair, DGCertSupportedAlgorithm.ES256, _keyid);
            }
            else
            {
                throw new System.NotSupportedException("Private key algorithm not supported");
            }

            return msg.EncodeToBytes();
        }
    }
}
