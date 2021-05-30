using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DGC
{
    public class SecretariatService : ISecretariatService
    {
        readonly Dictionary<string, List<X509Certificate>> trustedPublicKeys = new Dictionary<string, List<X509Certificate>>();

        public Task<IEnumerable<X509Certificate>> GetCertificate(string kid)
        {
            if (trustedPublicKeys.TryGetValue(kid, out var publicKeys))
            {
                return Task.FromResult(publicKeys.AsEnumerable());
            }
            else
            {
                return Task.FromResult(new List<X509Certificate>().AsEnumerable());
            }
        }

        public void AddPublicKey(string keyId, X509Certificate cert)
        {
            trustedPublicKeys.Add(keyId, new List<X509Certificate> { cert });
        }
    }
}
