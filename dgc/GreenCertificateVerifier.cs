using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
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
            var publicKeys = _secretariatService.GetPublicKeys(cwt.KID);
            if (publicKeys.Any())
            {
                foreach (var publicKey in publicKeys)
                {
                    var verified = VerifySignature(cwt, publicKey);
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

        private bool VerifySignature(CWT cwt, AsymmetricKeyParameter pubKey)
        {
            if (cwt.RegisteredAlgorithm == HCertSupportedAlgorithm.ES256)
            {
                ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signer.Init(false, pubKey);
                signer.BlockUpdate(cwt.Content, 0, cwt.Content.Length);
                return signer.VerifySignature(cwt.Signature);
            }
            else if (cwt.RegisteredAlgorithm == HCertSupportedAlgorithm.PS256)
            {
                ISigner signer = SignerUtilities.GetSigner("SHA256withRSA/PSS");
                signer.Init(false, pubKey);
                signer.BlockUpdate(cwt.Content, 0, cwt.Content.Length);
                return signer.VerifySignature(cwt.Signature);
            }
            return false;
        }
    }
}


