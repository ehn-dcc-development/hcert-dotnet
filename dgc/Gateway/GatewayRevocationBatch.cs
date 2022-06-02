using System;
using System.Collections.Generic;

namespace DCC.Gateway
{
    public class GatewayRevocationBatch
    {
        public string Country { get; set; }
        public DateTime Expires { get; set; }
        public string Kid { get; set; }
        public string HashType { get; set; }
        public IList<GatewayRevocationBatchEntry> Entries { get; set; }
    }

    public class GatewayRevocationBatchEntry
    {
        public string Hash { get;set; }
    }
}
