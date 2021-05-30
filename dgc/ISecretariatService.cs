using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DGC
{
    public interface ISecretariatService
    {
        Task<IEnumerable<X509Certificate>> GetCertificate(string kid);
    }
}