using System;
using System.Collections.Generic;

namespace wpt_etw
{
    public class CustomProvider
    {
        public int Verbosity { get; set; }

        public ulong Filter { get; set; }

        public IList<String> EventNames { get; set; }

        public IList<int> EventIDs { get; set; }
    }
}
