using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace DGC
{
    public class SecretariatService
    {
        readonly Dictionary<string, List<X509Certificate>> trustedPublicKeys = new Dictionary<string, List<X509Certificate>>();

        public IEnumerable<X509Certificate> GetCertificate(string kid)
        {
            if (trustedPublicKeys.TryGetValue(kid, out var publicKeys))
            {
                return publicKeys;
            }
            else
            {
                return new List<X509Certificate>();
            }
        }

        public void AddPublicKey(string keyId, X509Certificate cert)
        {
            trustedPublicKeys.Add(keyId, new List<X509Certificate> { cert });
        }
    }
}
