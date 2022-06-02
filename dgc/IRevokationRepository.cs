using System.Threading.Tasks;

namespace DCC
{
    public interface IRevocationRepository
    {
        Task<bool> ContainsHash(string kid, string issuingCountry, byte[] hash);
    }
}