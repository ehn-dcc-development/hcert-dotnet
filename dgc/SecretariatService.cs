using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

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

        public void AddPublicKey(AsymmetricKeyParameter publicKey)
        {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            string kid = Convert.ToBase64String(serializedPublicBytes).Substring(0, 8);

            trustedPublicKeys.Add(kid, new List<AsymmetricKeyParameter> { publicKey });
        }
    }
}