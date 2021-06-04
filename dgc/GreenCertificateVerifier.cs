using System;
using System.Linq;
using System.Threading.Tasks;

namespace DCC
{
    public class GreenCertificateVerifier
    {
        private readonly ISecretariatService _secretariatService;

        public GreenCertificateVerifier(ISecretariatService secretariatService)
        {
            _secretariatService = secretariatService;
        }

        /// <summary>
        /// Verify DGC 
        /// </summary>
        /// <param name="coseMessage">Cose message</param>
        /// <returns>(true, null) if valid, (false, reason) if not valid</returns>
        public async Task<Tuple<bool, string>> Verify(CWT cwt, DateTime? verifyClock = null)
        {
            if (!verifyClock.HasValue) verifyClock = DateTime.Now;

            var certificates = await _secretariatService.GetCertificate(cwt.CoseMessage.KID);
            if (certificates.Any())
            {
                bool? validSignature = null;
                foreach (var certificate in certificates)
                {
                    validSignature = cwt.CoseMessage.VerifySignature(certificate);
                }
                if (!validSignature.HasValue)
                    return Tuple.Create(false, "KID public key not found");
                if (!validSignature.Value)
                    return Tuple.Create(false, "Signature is not valid");
                if (cwt.ExpiarationTime < verifyClock.Value)
                    return Tuple.Create(false, "Certificate has expired");

                return Tuple.Create<bool, string>(true, null);
            }
            else
            {
                return Tuple.Create(false, "KID not found in trusted public key repository");
            }
        }        
    }
}


