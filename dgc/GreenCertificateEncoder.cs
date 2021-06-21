using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ICSharpCode.SharpZipLib.Zip.Compression;
using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using NL.MinVWS.Encoding;

namespace DCC
{
    public class GreenCertificateEncoder
    {
        private readonly X509Certificate2 _cert;
        private readonly string _keyid;

        public GreenCertificateEncoder(X509Certificate2 certificate)
        {
            _cert = certificate;

            using (var mySHA256 = System.Security.Cryptography.SHA256.Create())
            {
                var hash = mySHA256.ComputeHash(certificate.GetRawCertData());
                var hash8 = hash.Take(8).ToArray();
                _keyid = Convert.ToBase64String(hash8);
            }
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

            var ecdaKey = _cert.GetECDsaPrivateKey();
            
            if (ecdaKey != null)
            {
                msg.Sign(ecdaKey, _keyid);
                return msg.EncodeToBytes();
            }

            var rsaKey = _cert.GetRSAPrivateKey();
            if (rsaKey != null)
            { 
                msg.Sign(rsaKey, _keyid);
            }
            else
            {
                throw new System.NotSupportedException("Private key algorithm not supported");
            }

            return msg.EncodeToBytes();
        }
    }
}
