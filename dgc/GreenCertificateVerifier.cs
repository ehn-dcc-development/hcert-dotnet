using System;
using System.Linq;

namespace DGC
{
    public class GreenCertificateVerifier
    {
        private readonly SecretariatService _secretariatService;

        public GreenCertificateVerifier(SecretariatService secretariatService)
        {
            _secretariatService = secretariatService;
        }

        /// <summary>
        /// Verify DGC 
        /// </summary>
        /// <param name="coseMessage">Cose message</param>
        /// <returns>(true, null) if valid, (false, reason) if not valid</returns>
        public (bool, string) Verify(CWT cwt)
        {
            var certificates = _secretariatService.GetCertificate(cwt.CoseMessage.KID);
            if (certificates.Any())
            {
                bool? validSignature = null;
                foreach (var certificate in certificates)
                {
                    validSignature = cwt.CoseMessage.VerifySignature(certificate.GetPublicKey());
                }
                if (!validSignature.HasValue)
                    return (false, "KID public key not found");
                if (!validSignature.Value)
                    return (false, "Signature is not valid");
                if (cwt.ExpiarationTime < DateTime.Now)
                    return (false, "Certificate has expired");

                return (true, null);
            }
            else
            {
                return (false, "KID not found in trusted public key repository");
            }
        }        
    }
}


