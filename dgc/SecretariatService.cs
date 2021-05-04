using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DGC
{
    public class SecretariatService
    {
        readonly Dictionary<string, List<AsymmetricKeyParameter>> trustedPublicKeys = new Dictionary<string, List<AsymmetricKeyParameter>>();

        public IEnumerable<AsymmetricKeyParameter> GetPublicKeys(string kid)
        {
            if (trustedPublicKeys.TryGetValue(kid, out var publicKeys))
            {
                return publicKeys;
            }
            else
            {
                return new List<AsymmetricKeyParameter>();
            }
        }

        public void AddPublicKey(string keyId, AsymmetricKeyParameter publicKey)
        {
            trustedPublicKeys.Add(keyId, new List<AsymmetricKeyParameter> { publicKey });
        }
    }
}