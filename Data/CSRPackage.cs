using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DevCertDispenser.Data
{
    public class CSRPackage
    {
        public string CSRPath { get; set; }
        public bool UseSAN { get; set; }
        public string ConfigPath { get; set; }
    }
}
