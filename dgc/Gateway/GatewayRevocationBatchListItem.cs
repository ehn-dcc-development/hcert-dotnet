using System;

namespace DCC.Gateway
{
    public class GatewayRevocationBatchListItem
    {
        public string batchId { get; set; }
        public string country { get; set; }
        public DateTime date { get; set; }
        public bool deleted { get; set; }
    }
}
