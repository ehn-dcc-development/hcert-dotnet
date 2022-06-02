using System.Collections.Generic;

namespace DCC.Gateway
{
    public class GatewayRevocationBatchList
    {
        public bool More { get; set; }
        public IList<GatewayRevocationBatchListItem> Batches { get; set; }
    }
}
