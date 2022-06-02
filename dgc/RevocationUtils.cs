using System.Security.Cryptography;
using System.Text;

namespace DCC
{
    public static class RevocationUtils
    {
        public static SHA256 SHA256 = SHA256.Create();
        public static byte[] ComputeUCIHash(CWT cwt)
        {
            string uci = "";

            if (cwt.DGCv1.Vaccination.Length > 0) uci = cwt.DGCv1.Vaccination[0].CertificateIdentifier;
            else if (cwt.DGCv1.Recovery.Length > 0) uci = cwt.DGCv1.Recovery[0].CertificateIdentifier;
            else if (cwt.DGCv1.Test.Length > 0) uci = cwt.DGCv1.Test[0].CertificateIdentifier;

            return SHA256.ComputeHash(Encoding.UTF8.GetBytes(uci))[0..16];
        }

        public static byte[] ComputeContryCodeUCIHash(CWT cwt)
        {
            string uci = "";

            if (cwt.DGCv1.Vaccination.Length > 0) uci = cwt.DGCv1.Vaccination[0].CountryOfVaccination + cwt.DGCv1.Vaccination[0].CertificateIdentifier;
            else if (cwt.DGCv1.Recovery.Length > 0) uci = cwt.DGCv1.Recovery[0].CountryOfTest + cwt.DGCv1.Recovery[0].CertificateIdentifier;
            else if (cwt.DGCv1.Test.Length > 0) uci = cwt.DGCv1.Test[0].CountryOfTest + cwt.DGCv1.Test[0].CertificateIdentifier;

            return SHA256.ComputeHash(Encoding.UTF8.GetBytes(uci))[0..16];
        }

        public static byte[] ComputeSignatureHash(CWT cwt)
        {
            /* In this case the hash is calculated over the bytes of the COSE_SIGN1 signature from the CWT. 
             * For RSA signatures, the entire signature will be used as input.
             * The formula for the EC-DSA signed certificates is using the the r value as an input: SHA256(r) */
            if (cwt.CoseMessage.RegisteredAlgorithm == DGCertSupportedAlgorithm.ES256)
            {
                var signlength = cwt.CoseMessage.Signature.Length;
                return SHA256.ComputeHash(cwt.CoseMessage.Signature[0..(signlength/2)])[0..16];
            }
            else if (cwt.CoseMessage.RegisteredAlgorithm == DGCertSupportedAlgorithm.PS256)
            {
                return SHA256.ComputeHash(cwt.CoseMessage.Signature)[0..16];
            }
            else
            {
                throw new System.Exception("Signature algorithm not supported");
            }
        }
    }
}
