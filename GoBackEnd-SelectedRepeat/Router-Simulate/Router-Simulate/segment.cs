using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Router_Simulate
{
    class segment
    {
        private byte[] Data;//byte array for segment

        public byte[] data
        {
            get { return Data; }
            set { Data = value; }
        }
        private bool Reached_dest;//segment received

        public bool reached_dest
        {
            get { return Reached_dest; }
            set { Reached_dest = value; }
        }
        private int Packet_pos;//packet position

        public int packet_pos
        {
            get { return Packet_pos; }
            set { Packet_pos = value; }
        }

        public segment()
        {

        }
        private bool Packet_ack;

        public bool packet_ack
        {
            get { return Packet_ack; }
            set { Packet_ack = value; }
        }
    }
}
