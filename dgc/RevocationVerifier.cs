using System.Threading.Tasks;

namespace DCC
{
    public class RevocationVerifier
    {
        private readonly IRevocationRepository _revokationRepository;

        public RevocationVerifier(IRevocationRepository revokationRepository)
        {
            _revokationRepository=revokationRepository;
        }

        public async Task<bool> IsRevoked(CWT cwt)
        {
            if (await _revokationRepository.ContainsHash(cwt.CoseMessage.KID, cwt.Issuer, RevocationUtils.ComputeUCIHash(cwt))) return true;
            if (await _revokationRepository.ContainsHash(cwt.CoseMessage.KID, cwt.Issuer, RevocationUtils.ComputeContryCodeUCIHash(cwt))) return true;
            if (await _revokationRepository.ContainsHash(cwt.CoseMessage.KID, cwt.Issuer, RevocationUtils.ComputeSignatureHash(cwt))) return true;

            return false;
        }
    }
}
