using System;
using System.Collections.Generic;

namespace DCC.Gateway
{
    public class GatewayRevocationBatch
    {
        public string country { get; set; }
        public DateTime expires { get; set; }
        public string kid { get; set; }
        public string hashType { get; set; }
        public List<GatewayRevocationBatchEntry> entries { get; set; }
    }

    public class GatewayRevocationBatchEntry
    {
        public string hash { get;set; }
    }
}
