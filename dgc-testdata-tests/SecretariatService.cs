using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DGC
{
    public class SecretariatService : DCC.ISecretariatService
    {
        readonly Dictionary<string, List<X509Certificate2>> trustedPublicKeys = new Dictionary<string, List<X509Certificate2>>();

        public Task<IReadOnlyList<X509Certificate2>> GetCertificate(string kid)
        {
            if (trustedPublicKeys.TryGetValue(kid, out var publicKeys))
            {
                return Task.FromResult((IReadOnlyList<X509Certificate2>)publicKeys);
            }
            else
            {
                return Task.FromResult((IReadOnlyList<X509Certificate2>)new List<X509Certificate2>());
            }
        }

        public void AddPublicKey(string keyId, X509Certificate2 cert)
        {
            trustedPublicKeys.Add(keyId, new List<X509Certificate2> { cert });
        }
    }
}
