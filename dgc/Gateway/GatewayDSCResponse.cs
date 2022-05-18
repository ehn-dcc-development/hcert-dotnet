using System;

namespace DCC.Gateway
{
    public class GatewayDSCResponse
    {
        public string kid { get; set; }
        public DateTime timestamp { get; set; }
        public string country { get; set; }
        public string certificateType { get; set; }
        public string thumbprint { get; set; }
        public string signature { get; set; }
        public string rawData { get; set; }
    }
}
