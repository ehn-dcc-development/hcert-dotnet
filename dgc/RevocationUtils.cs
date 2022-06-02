using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace DCC
{
    public static class RevocationUtils
    {
        public static byte[] ComputeUCIHash(CWT cwt)
        {
            string uci = "";

            if (cwt.DGCv1.Vaccination.Length > 0) uci = cwt.DGCv1.Vaccination[0].CertificateIdentifier;
            else if (cwt.DGCv1.Recovery.Length > 0) uci = cwt.DGCv1.Recovery[0].CertificateIdentifier;
            else if (cwt.DGCv1.Test.Length > 0) uci = cwt.DGCv1.Test[0].CertificateIdentifier;

            var sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(uci)[0..16]);
        }

        public static byte[] ComputeContryCodeUCIHash(CWT cwt)
        {
            string uci = "";

            if (cwt.DGCv1.Vaccination.Length > 0) uci = cwt.DGCv1.Vaccination[0].CountryOfVaccination + cwt.DGCv1.Vaccination[0].CertificateIdentifier;
            else if (cwt.DGCv1.Recovery.Length > 0) uci = cwt.DGCv1.Recovery[0].CountryOfTest + cwt.DGCv1.Recovery[0].CertificateIdentifier;
            else if (cwt.DGCv1.Test.Length > 0) uci = cwt.DGCv1.Test[0].CountryOfTest + cwt.DGCv1.Test[0].CertificateIdentifier;

            var sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(uci)[0..16]);
        }

        public static byte[] ComputeSignatureHash(CWT cwt)
        {
            var sha256 = SHA256.Create();

            // RSA uses entire sig, EC-DSA uses R, which is first half of the signature
            var bytesToHash = cwt.CoseMessage.RegisteredAlgorithm == DGCertSupportedAlgorithm.ES256
                ? cwt.CoseMessage.Signature
                : cwt.CoseMessage.Signature[0..(cwt.CoseMessage.Signature.Length / 2)];
            
            return sha256.ComputeHash(bytesToHash)[0..16];
        }
    }
}
