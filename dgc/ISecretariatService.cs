using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DCC
{
    public interface ISecretariatService
    {
        Task<IReadOnlyList<X509Certificate2>> GetCertificate(string kid);
    }
}