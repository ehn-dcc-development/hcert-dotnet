using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace dgc.testdata.tests
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await DGCTestDataVerifier.TestAll();
        }
    }
}
