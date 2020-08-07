using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace Tool.TimeZoneMap
{
    internal class ZoneMapInfo
    {
        public Dictionary<string, string> Map { get; private set; } = new Dictionary<string, string>();

        public int SrcMax { get; private set; }

        public int DestMax { get; private set; }
        
        internal void Add(string src, string dest)
        {
            if(this.Map.TryAdd(src, dest))
            {
                this.SrcMax  = Math.Max(this.SrcMax,  src.Length);
                this.DestMax = Math.Max(this.DestMax, dest.Length);
            }
        }

    }
}
