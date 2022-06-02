using System;

namespace DCC.Gateway
{
    public class GatewayDSCResponse
    {
        public string Kid { get; set; }
        public DateTime Timestamp { get; set; }
        public string Country { get; set; }
        public string CertificateType { get; set; }
        public string Thumbprint { get; set; }
        public string Signature { get; set; }
        public string RawData { get; set; }
    }
}
