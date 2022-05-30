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
            else if (cwt.DGCv1.Recovery.Length > 0) uci = cwt.DGCv1.Recovery[0].CountryOfVaccination + cwt.DGCv1.Recovery[0].CertificateIdentifier;
            else if (cwt.DGCv1.Test.Length > 0) uci = cwt.DGCv1.Test[0].CountryOfVaccination + cwt.DGCv1.Test[0].CertificateIdentifier;

            var sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(uci)[0..16]);
        }

        public static byte[] ComputeSignatureHash(CWT cwt)
        {
            var sha256 = SHA256.Create();
            var signlength = cwt.CoseMessage.Signature.Length;
            return sha256.ComputeHash(cwt.CoseMessage.Signature[0..(signlength/2)])[0..16];
        }
    }
}
