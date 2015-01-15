using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Router_Simulate
{
    class Probability
    {
        private int index;//index
        private bool used;//used before

        public Probability()
        {
            used = false;
            index = -1;
        }


        public bool Used
        {
            get { return used; }
            set { used = value; }
        }

        public int Index
        {
            get { return index; }
            set { index = value; }
        }
    }
}
