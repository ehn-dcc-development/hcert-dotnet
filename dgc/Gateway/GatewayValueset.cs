using System;

namespace DCC.Gateway
{
    public class GatewayValueset
    {
        public string Value { get; set; }
        public string SetId { get; set; }
        public DateTime SetDate { get; set; }
        public string Display { get; set; }
        public string Lang { get; set; }
        public bool Active { get; set; }
        public string Version { get; set; }
        public string System { get; set; }

        public override string ToString()
        {
            return Display;
        }
    }
}
