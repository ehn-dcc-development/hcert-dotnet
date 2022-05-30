using System.Collections.Generic;

namespace DCC.Gateway
{
    public class GatewayRevocationBatchList
    {
        public bool more { get; set; }
        public List<GatewayRevocationBatchListItem> batches { get; set; }
    }
}
