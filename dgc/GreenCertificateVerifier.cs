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
            var publicKeys = _secretariatService.GetPublicKeys(cwt.CoseMessage.KID);
            if (publicKeys.Any())
            {
                foreach (var publicKey in publicKeys)
                {
                    var verified = cwt.CoseMessage.VerifySignature(publicKey);
                    if (cwt.ExpiarationTime < DateTime.Now)
                        return (false, "Certificate has expired");
                    if (verified) return (true, null);
                }
                return (false, "KID public key does not match signature");
            }
            else
            {
                return (false, "KID not found in trusted public key repository");
            }
        }        
    }
}


