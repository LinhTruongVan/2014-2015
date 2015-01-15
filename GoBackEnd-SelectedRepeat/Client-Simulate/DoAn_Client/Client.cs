using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Diagnostics;
using DevExpress.XtraEditors;
using DevExpress.Skins;
using DevExpress.Data;
using DevExpress.Utils.Controls;

namespace DoAn_Client
{
    public partial class Client : XtraForm
    {
        private byte[] file = new byte[1024*1500];//Byte Array for file
        private segment[] segments = new segment[20];//Segments' Array
        private int index = 0;//Index for Segments' Array
        private bool corrupt_segment = false;//Corrupt Segment
        private double probability = 1;//Probability for Segment Corruption
        private int corrupted_packets = 0;//number of segments which will be corrupted
        private Probability[] corrupt_index;//Array for Segments' indexes whose Segment will be corrupted
        private object lockvar = string.Empty;//Object to Synchronize Threads
        private int window_size = 0;//Window Size 
        string ipRouter;

        //
        //
        //
        private segment[] segmentsReceived = new segment[20];//Array for 40 segmentsReceived
        private int indexReceived = -1; //Index for segmentsReceived rray
        private bool corrupt_ACK = false; //Acknowledge corrupt
        private double probability_ACK = 1; //Probability of Acknowledge corrupt in channel
        private int corrupted_ACKs = 0; //number of corrupted ACKs
        private Probability[] corruptedACKs_index; //Array for segmentsReceived' indexes whose ACK will be corrupet

        public Client()
        {
            InitializeComponent();//Initialize Controls
            DevExpress.Skins.SkinManager.EnableFormSkins();
            DevExpress.UserSkins.BonusSkins.Register();
            this.MaximumSize = this.MinimumSize = this.Size;
        }

        private void SendSegment()
        {
            try
            {
                segment seg = segments[index];//Segment
                seg.packet_pos = ++index;//Increase index and set packet position 
                seg.packet_ack = false;//packet ack is not received

                byte[] data = new byte[76803];//76803 Byte long Array
                string response = string.Empty;//Response from Receiver Side

                IPEndPoint ipep = new IPEndPoint(IPAddress.Parse(ipRouter), 9999);//Server IP Address and Port Number
                Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);//TCP connection
                server.Connect(ipep);//Connect to Server(Receiver Side)
                int recv = server.Receive(data);//Receive "Welcome" msg
                //response = Encoding.ASCII.GetString(data, 0, recv);//Decode msg 

                data = new byte[76803];//76803 Byte long Array for segment
                for (int i = 0; i < 76800; i++)
                {
                    data[i] = seg.data[i];//Fill segment
                }


                //adding sequence number
                if (seg.packet_pos > 9)
                {
                    int tens = seg.packet_pos / 10;
                    int ones = seg.packet_pos % 10;
                    data[76800] = Encoding.ASCII.GetBytes(tens.ToString())[0];
                    data[76801] = Encoding.ASCII.GetBytes(ones.ToString())[0];

                }
                else
                {
                    data[76800] = Encoding.ASCII.GetBytes("0")[0];
                    data[76801] = Encoding.ASCII.GetBytes(seg.packet_pos.ToString())[0];
                }
                corrupt_segment = false;//corrupt segment is set to false

                if (checkCorruptSegment.Checked)//Check corrupt probability is set or not
                {
                    for (int i = 0; i < corrupt_index.Length; i++)
                    {
                        if (seg.packet_pos == corrupt_index[i].Index && !corrupt_index[i].Used)//Check packet_number, corrupted indexes and index is used before 
                        {
                            corrupt_segment = true;//Corrupt segment is enable
                            corrupt_index[i].Used = true;//Used before
                        }
                    }
                }

                if (corrupt_segment)//Check corrupt_segment
                {
                    data[76802] = Encoding.ASCII.GetBytes("1")[0];// 0-> not corrupted 1-> corrupted
                }
                else
                {
                    data[76802] = Encoding.ASCII.GetBytes("0")[0];// 0-> not corrupted 1-> corrupted
                }


                int send = server.Send(data, data.Length, SocketFlags.None);//Send Segment
                data = new byte[4];//4 Byte long array
                recv = server.Receive(data);//Receive response
                response = Encoding.ASCII.GetString(data, 0, recv);//Decode response msg
                if (response.Trim() == "ACK")//Check Segment ACK is received
                {
                    seg.packet_ack = true;//Segment ACK is received
                    foreach (Control var in this.gbSegments.Controls)
                    {
                        if (var is Label && (var.Name == "label" + seg.packet_pos.ToString()))
                        {
                            var.BackColor = Color.Yellow;//Segment ACK is received
                        }
                    }
                }
                if (response.Trim() == "NACK")//Check Segment ACK is Not received
                {
                    seg.packet_ack = false;//Segment ACK is not received
                    foreach (Control var in this.gbSegments.Controls)
                    {
                        if (var is Label && (var.Name == "label" + seg.packet_pos.ToString()))
                        {
                            var.BackColor = Color.DodgerBlue;//Segment ACK is NOT received
                        }
                    }
                }

                server.Shutdown(SocketShutdown.Both);//Server Socket is not allowed
                server.Close();//server connection is closed.
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message.ToString(), "Failure", MessageBoxButtons.OK, MessageBoxIcon.Error);//Exception Message is shown
            }
        }

        /// <summary>
        /// Send Segment according to its position
        /// </summary>
        /// <param name="position"></param>
        private void SendSegments(int position)
        {
            lock (lockvar)//Synchronize threads 
            {
                try
                {

                    segment seg = segments[position - 1];//Segment
                    seg.packet_pos = position;//set packet position 
                    seg.packet_ack = false;//packet ack is not received


                    byte[] data = new byte[76803];//76803 Byte long Array
                    string response = string.Empty;//Response from Receiver Side
                    IPEndPoint ipep = new IPEndPoint(IPAddress.Parse(ipRouter), 9999);//Server IP Address and Port Number
                    Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);//TCP connection

                    server.Connect(ipep);//Connect to Server(Receiver Side)
                    int recv = server.Receive(data);//Receive "Welcome" msg
                    response = Encoding.ASCII.GetString(data, 0, recv);//Decode msg 

                    data = new byte[76803];//76803 Byte long Array for segment
                    for (int i = 0; i < 76800; i++)
                    {
                        data[i] = seg.data[i];//Fill segment
                    }


                    //adding sequence number
                    if (seg.packet_pos > 9)
                    {
                        int tens = seg.packet_pos / 10;
                        int ones = seg.packet_pos % 10;
                        data[76800] = Encoding.ASCII.GetBytes(tens.ToString())[0];
                        data[76801] = Encoding.ASCII.GetBytes(ones.ToString())[0];
                    }
                    else
                    {
                        data[76800] = Encoding.ASCII.GetBytes("0")[0];
                        data[76801] = Encoding.ASCII.GetBytes(seg.packet_pos.ToString())[0];
                    }

                    data[76802] = Encoding.ASCII.GetBytes("0")[0];// 0-> not corrupted 1-> corrupted

                    int send = server.Send(data, data.Length, SocketFlags.None);//Send Segment
                    data = new byte[4];//4 Byte long array
                    recv = server.Receive(data);//Receive response
                    response = Encoding.ASCII.GetString(data, 0, recv);//Decode response msg
                    if (response.Trim() == "ACK")//Check Segment ACK is received or not
                    {
                        // MessageBox.Show("packet received"+Encoding.ASCII.GetString(seg.data, 0, seg.data.Length));
                        seg.packet_ack = true;//Segment ACK is received
                        foreach (Control var in this.gbSegments.Controls)
                        {
                            if (var is Label && (var.Name == "label" + seg.packet_pos.ToString()))
                            {
                                var.BackColor = Color.Yellow;//Segment ACK is received
                            }
                        }
                    }
                    if (response.Trim() == "NACK")//Check Segment ACK is Not received
                    {
                        seg.packet_ack = false;//Segment ACK is not received
                        foreach (Control var in this.gbSegments.Controls)
                        {
                            if (var is Label && (var.Name == "label" + seg.packet_pos.ToString()))
                            {
                                var.BackColor = Color.DodgerBlue;
                            }
                        }
                    }
                    server.Shutdown(SocketShutdown.Both);//Server Socket is not allowed
                    server.Close();//server connection is closed.
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message.ToString(), "Failure", MessageBoxButtons.OK, MessageBoxIcon.Error);//Exception Message is shown
                }
            }
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            bool firstSend = true;//First time Segment Sending
            int window_size_tempt = (int)numWindowSize.Value;

            if (index > 0 && index <= 20)//Check index
            {
                if (checkGBN.Checked == true)
                {
                    if (index == window_size)
                    {
                        for (int i = 0; i < index; i++)
                        {
                            if (segments[i].packet_ack == false)//Check previous packets' ACKS
                            {
                                //for (int j = 0; j < index; j++)
                                //{
                                //    SendSegments(j + 1);//Resend Segments
                                //}
                                //firstSend = false;//first send
                                //break;
                                for (int j = i; j < i + window_size; j++)
                                {
                                    SendSegments(j + 1);
                                    window_size_tempt--;
                                }
                            }
                        }
                    }
                    else
                    {
                        for (int i = index - window_size; i < index; i++)
                        {
                            if (segments[i].packet_ack == false)//Check previous packets' ACKS
                            {
                                //for (int j = index - window_size; j < index; j++)
                                //{
                                //    SendSegments(j + 1);//Resend Segments
                                //}
                                //firstSend = false;//first send
                                //break;
                                for (int j = i; j < i + window_size; j++)
                                {
                                    SendSegments(j + 1);
                                    window_size_tempt--;
                                }
                            }
                        }
                    }
                    if (firstSend)
                    {
                        window_size = (int)numWindowSize.Value;//window size is set
                        int delay = (int)numDelay.Value;//delay value in microsecs
                        Thread[] threads = new Thread[window_size_tempt];//Multiple threads
                        for (int i = 0; i < window_size_tempt; i++)
                        {
                            threads[i] = new Thread(new ThreadStart(SendSegment));//Construct threads
                            threads[i].Start();//Thread starts
                            Thread.Sleep(delay);//Threads sleep
                        }
                    }
                }
                else
                {
                    if (index == window_size)
                    {
                        for (int i = 0; i < index; i++)
                        {
                            if (segments[i].packet_ack == false)//Check previous packets' ACKS
                            {
                                SendSegments(i + 1);//Resend Segments
                                window_size_tempt--;
                            }
                        }
                    }
                    else
                    {
                        for (int i = index - window_size; i < index; i++)
                        {
                            if (segments[i].packet_ack == false)//Check previous packets' ACKS
                            {
                                SendSegments(i + 1);//Resend Segments
                                window_size_tempt--;
                            }
                        }
                    }
                    if (firstSend)
                    {
                        window_size = (int)numWindowSize.Value;//window size is set
                        int delay = (int)numDelay.Value;//delay value in microsecs
                        Thread[] threads = new Thread[window_size_tempt];//Multiple threads
                        for (int i = 0; i < window_size_tempt; i++)
                        {
                            threads[i] = new Thread(new ThreadStart(SendSegment));//Construct threads
                            threads[i].Start();//Thread starts
                            Thread.Sleep(delay);//Threads sleep
                        }
                    }

                }

            }

            if (index == 0 && firstSend)
            {
                window_size = (int)numWindowSize.Value;//window size is set
                int delay = (int)numDelay.Value;//delay value in microsecs
                Thread[] threads = new Thread[window_size];//Multiple threads
                for (int i = 0; i < window_size; i++)
                {
                    threads[i] = new Thread(new ThreadStart(SendSegment));//Construct threads
                    threads[i].Start();//Thread starts
                    Thread.Sleep(delay);//Threads sleep
                }
            }
        }

        private void Client_Load(object sender, EventArgs e)
        {
            lblClientState.Text = "Please Upload One File To Send !!!";
            btnSend.Enabled = false;//bntConnect is disabled default
            ipRouter = tbIpRouter.Text;

            Thread listen = new Thread(new ThreadStart(Listen));
            listen.Start();

            foreach (Control var in this.gbSegments.Controls)//Check controls in form
            {
                if (var is Label && var.Name.StartsWith("label"))
                {
                    var.Text = var.Text.Replace("label", "#");
                }
            }

            probability = 1 / ((double)numProbability.Value);//probability value is calculated
            corrupted_packets = (int)(probability * 20);//number of corrupted ACKs calculated
            corrupt_index = new Probability[corrupted_packets];//Probability array is created

            Random random = new Random();//Random number for Corrupted ACKS Index
            for (int i = 0; i < corrupt_index.Length; i++)
            {
                corrupt_index[i] = new Probability();//Member is constructed
                corrupt_index[i].Used = false;//Not used
                int rand = random.Next(0, 20);
                for (int j = 0; j < i - 1; j++)
                {
                    if (corrupt_index[j].Index == rand)
                    {
                        rand = random.Next(0, 20);//a random number is selected between 0 to 20
                        for (int k = 0; k < j - 1; k++)
                        {
                            if (corrupt_index[k].Index == rand)//check other indexes
                            {
                                rand = random.Next(0, 20);//a random number is selected between 0 to 20
                                for (int m = 0; m < k - 1; m++)
                                {
                                    if (corrupt_index[m].Index == rand)//check other indexes
                                    {
                                        rand = random.Next(0, 20);//a random number is selected between 0 to 20
                                    }
                                }
                            }
                        }
                    }
                }
                corrupt_index[i].Index = rand;//add random number in index
            }
            //
            //
            //
            for (int i = 0; i < 20; i++)
            {
                segmentsReceived[i] = new segment();//Segments' array's members are constructed
                segmentsReceived[i].data = new byte[76800];
            }
            foreach (Control var in this.gbSegmentReceived.Controls)
            {
                if (var is Label)
                {
                    var.Text = var.Text.Replace("label", "#");//Labels' texts are changed to "Segment#"
                }
            }
            probability_ACK = 1 / ((double)numProbabilityACK.Value);//probability value is calculated
            corrupted_ACKs = (int)(probability_ACK * 20);//number of corrupted ACKs calculated
            corruptedACKs_index = new Probability[corrupted_ACKs];//Probability array is created


            for (int i = 0; i < corruptedACKs_index.Length; i++)
            {
                corruptedACKs_index[i] = new Probability();//Member is constructed
                corruptedACKs_index[i].Used = false;//Not used
                int rand = random.Next(0, 20);//a random number is selected between 0 to 40

                for (int j = 0; j < i - 1; j++)
                {
                    if (corruptedACKs_index[j].Index == rand)//check other indexes
                    {
                        rand = random.Next(0, 20);

                        for (int k = 0; k < j - 1; k++)
                        {
                            if (corruptedACKs_index[k].Index == rand)//check other indexes
                            {
                                rand = random.Next(0, 20);

                                for (int m = 0; m < k - 1; m++)
                                {
                                    if (corruptedACKs_index[m].Index == rand)//check other indexes
                                    {
                                        rand = random.Next(0, 20);
                                    }
                                }
                            }
                        }
                    }
                }
                corruptedACKs_index[i].Index = rand;//add random number in index

            }
        }

        private void btnUploadFile_Click(object sender, EventArgs e)
        {
            index = 0;//index is set to zero
            for (int i = 0; i < 20; i++)
            {
                segments[i] = new segment();//Segment member created
                segments[i].data = new byte[76800];//Byte array created
            }

            OpenFileDialog ofd = new OpenFileDialog();//Open File Dialog 
            ofd.Title = "Select a text file to Send";
            ofd.Filter = "Text Files (*.txt)|*.txt|Document File (*.doc)|*.doc|PNG file (*.png)|*.png";//File Type txt
            if (ofd.ShowDialog(this) == DialogResult.OK)//Check file is selected or not
            {
                //FileStream fs = new FileStream(ofd.FileName, FileMode.Open);//FileStream is created
                //file = ReadFully(fs, 1024*1500);//1024*1500 Byte is read
                file = File.ReadAllBytes(ofd.FileName);
                if (file.Length < 76800)
                {
                    for (int i = 0; i < file.Length; i++)
                        segments[0].data[i] = file[i];
                }
                else
                {
                    for (int i = 0; i < 20; i++)
                    {
                        for (int j = 0; j < 76800; j++)
                        {
                            if (i * 76800 + j >= file.Length)
                            {
                                break;
                            }
                            else
                            {
                                segments[i].data[j] = file[i * 76800 + j];
                            }
                        }
                    }
                }

                lblClientState.Text = "20 Segments with 76800Bytes  are ReaDy to Send!..";
                btnSend.Enabled = true;//Enable bntConnect
                foreach (Control var in this.gbSegments.Controls)
                {
                    if (var is Label && var.Name.StartsWith("label"))
                    {

                        var.BackColor = Color.PaleGreen;//Segments are ready to send.
                    }
                }
                //fs.Close();//Filestream is closed.
            }
        }

        public static byte[] ReadFully(Stream stream, int dimension)
        {
            byte[] buffer = new byte[dimension];//A byte array with "dimension" long
            using (MemoryStream ms = new MemoryStream())//Memory stream
            {
                while (true)
                {
                    int read = stream.Read(buffer, 0, buffer.Length);
                    if (read <= 0)//check number of bytes read
                        return ms.ToArray();//if number of bytes read is zero or negative, return byte array
                    ms.Write(buffer, 0, read);//writes a block of bytes to the current stream using data read from buffer
                }
            }
        }



        private void numWindowSize_ValueChanged(object sender, EventArgs e)
        {
            window_size = (int)numWindowSize.Value;//Window Size is set
        }



        private void checkGBN_CheckedChanged(object sender, EventArgs e)
        {
            checkSR.Checked = !checkGBN.Checked;
        }

        private void checkSR_CheckedChanged(object sender, EventArgs e)
        {
            checkGBN.Checked = !checkSR.Checked;
        }

        private void checkNoCorruptSegment_CheckedChanged(object sender, EventArgs e)
        {
            checkCorruptSegment.Checked = !checkNoCorruptSegment.Checked;
        }

        private void checkCorruptSegment_CheckedChanged(object sender, EventArgs e)
        {
            checkNoCorruptSegment.Checked = !checkCorruptSegment.Checked;
        }

        private void checkNoCorruptACK_CheckedChanged(object sender, EventArgs e)
        {
            checkCorruptACK.Checked = !checkNoCorruptACK.Checked;
        }

        private void checkCorruptACK_CheckedChanged(object sender, EventArgs e)
        {
            checkNoCorruptACK.Checked = !checkCorruptACK.Checked;
        }
        ///
        ///
        ///
        ///
        ///
        ///
        ///
        private void numProbabilityACK_ValueChanged(object sender, EventArgs e)
        {
            probability_ACK = 1 / ((double)numProbability.Value);//probability value is calculated
            corrupted_ACKs = (int)(probability_ACK * 20);//number of corrupted ACKs calculated
            corruptedACKs_index = new Probability[corrupted_ACKs];//Probability array is created

            Random random = new Random();//Random number for Corrupted ACKS Index

            for (int i = 0; i < corruptedACKs_index.Length; i++)
            {
                corruptedACKs_index[i] = new Probability();//Member is constructed
                corruptedACKs_index[i].Used = false;//Not used
                int rand = random.Next(0, 20);//a random number is selected between 0 to 40

                for (int j = 0; j < i - 1; j++)
                {
                    if (corruptedACKs_index[j].Index == rand)//check other indexes
                    {
                        rand = random.Next(0, 20);

                        for (int k = 0; k < j - 1; k++)
                        {
                            if (corruptedACKs_index[k].Index == rand)//check other indexes
                            {
                                rand = random.Next(0, 20);

                                for (int m = 0; m < k - 1; m++)
                                {
                                    if (corruptedACKs_index[m].Index == rand)//check other indexes
                                    {
                                        rand = random.Next(0, 20);
                                    }
                                }
                            }
                        }
                    }
                }
                corruptedACKs_index[i].Index = rand;//add random number in index
            }
        }

        private void btnDownload_Click(object sender, EventArgs e)
        {
            try
            {
                bool DownloadEnable = false;//DownloadEnable is set to false
                for (int i = 0; i < 20; i++)
                {
                    if (segmentsReceived[i].reached_dest == false)//Check segments
                    {
                        DownloadEnable = false;//if any segments not received, DownloadEnable is set to false
                        break;//break loop
                    }
                    else
                    {
                        DownloadEnable = true;//Download is now avaiable
                        if (indexReceived == 19)
                            indexReceived++;
                    }
                }

                if (indexReceived >= 20 && DownloadEnable)//check index and DownloadEnable
                {
                    SaveFileDialog sfd = new SaveFileDialog();//Create SaveFileDialog
                    sfd.Title = "Select a text file";//Title
                    sfd.Filter = "Text Files (*.txt)|*.txt|Document File (*.doc)|*.doc|PNG file (*.png)|*.png";//File Type

                    if (sfd.ShowDialog(this) == DialogResult.OK)//check file name is selected or not
                    {
                        FileStream fs = new FileStream(sfd.FileName, FileMode.Create);//create file stream
                        //StreamWriter swtr = new StreamWriter(fs, Encoding.GetEncoding("ISO-8859-9"));//Stream Writer which uses Turkish Encoding
                        BinaryWriter bWrite = new BinaryWriter(fs, Encoding.GetEncoding("ISO-8859-9"));

                        byte[] receivedData = new byte[1024*1500];//Our segments are total 1024*1500 byte data.

                        for (int i = 0; i < 20; i++)
                        {
                            for (int j = 0; j < 76800; j++)
                            {
                                receivedData[i * 76800 + j] = segmentsReceived[i].data[j];//Combine all segments in receivedData
                            }
                        }
                        //string words = Encoding.ASCII.GetString(receivedData, 0, 1024*1500);//Decode receivedData to ASCII format
                        //swtr.WriteLine(words);//Write string to file stream fs
                        bWrite.Write(receivedData);
                        bWrite.Close();
                        fs.Close();//file stream is closed.

                        Process process = new Process();//Process for open text file
                        process.StartInfo.FileName = sfd.FileName;//File Name is set
                        process.StartInfo.Verb = "Open";//Command
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();//Open text file
                    }
                }
                else
                {
                    MessageBox.Show("No File Received or File is Corrupted!...", "Failure");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error);//Exception Message is shown
            }
        }

        private void Listen()
        {
            try
            {
                //string response;//The msg taken from sender side
                int recv;//Number
                int packet_number;//Packet Number
                bool work = true;//Boolean variable for while loop
                IPEndPoint ipep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8888);//IPEndPoint with 127.0.0.1 IP and 8888 port number
                Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);//TCP connection
                newsock.Bind(ipep);//Combine IP and Socket
                newsock.Listen(20);//Maximum lenght of the pending connection queue is set to 40
                byte[] data;//Byte array for segment

                foreach (Control var in this.gbSegmentReceived.Controls)//Check Controls in Form
                {
                    for (int i = 1; i < 21; i++)
                    {
                        if (var is Label && (var.Name == "SegmentR" + i.ToString()))// Checks control is label && its name starts with "label or not"
                        {
                            var.BackColor = Color.Gold;//Change Color to Gold
                        }
                    }
                }

                while (work)//Infinite Loop until work is set to false
                {
                    data = new byte[76803];//new 76803 byte long array
                    Socket client = newsock.Accept();//Server waits for client.If it finds then it opens a new socket for connection

                    data = Encoding.ASCII.GetBytes("Welcome");//Welcome msg is encoded to byte format
                    client.Send(data, data.Length, SocketFlags.None);//msg is sent

                    data = new byte[76803];//new 76803 byte long array

                    recv = client.Receive(data);//Receive Segment from sender side

                    byte[] packet_tag = new byte[3];//3 Byte long Byte Array

                    packet_tag[0] = data[76800];//Take Byte from Segment
                    packet_tag[1] = data[76801];//Take Byte from Segment
                    packet_tag[2] = data[76802];//Take Byte from Segment

                    packet_number = Convert.ToInt16(Encoding.ASCII.GetString(packet_tag, 0, 2));//76800th and 76801th Byte shows the packet number.
                    int corrupted = Convert.ToInt16(Encoding.ASCII.GetString(packet_tag, 2, 1));//76802th byte determines whether segment is corrupted or not.

                    indexReceived = packet_number;//Refresh index

                    if (packet_number >= 25)//Checks packet number is bigger than 45 or not
                    {
                        work = false;//while loop will end

                    }

                    for (int i = 0; i < 76800; i++)
                    {
                        segmentsReceived[packet_number - 1].data[i] = data[i];//Adding received segment to segmentsReceived' Arraay
                    }


                    // response = Encoding.ASCII.GetString(segmentsReceived[packet_number - 1].data, 0, 76800);

                    corrupt_ACK = false;//Corrupt ACK is default to set false
                    if (corrupted == 0)//Check corrupted. 0-> Segment NOT Corrupted, 1->Segment Corrupted 
                    {
                        segmentsReceived[packet_number - 1].reached_dest = true;//Segment Received
                        segmentsReceived[packet_number - 1].packet_pos = packet_number;//Segment packet position is set

                        if (checkCorruptACK.Checked)//Check whether ACK corrupt probability is set or not
                        {
                            for (int i = 0; i < corruptedACKs_index.Length; i++)
                            {
                                if (corruptedACKs_index[i].Index == packet_number && !corruptedACKs_index[i].Used)//Check packet_number, corrupted indexes and index is used before 
                                {

                                    data = new byte[4];//4 byte long byte array
                                    data = Encoding.ASCII.GetBytes("NACK");//NACK is encoded to byte format
                                    client.Send(data, data.Length, SocketFlags.None);//NACK is sent to Sender Side

                                    corruptedACKs_index[i].Used = true;//Index will not be used  
                                    corrupt_ACK = true;//ACK is corrupted

                                    foreach (Control var in this.gbSegmentReceived.Controls)//Checks all controls in Form
                                    {
                                        if (var is Label && (var.Name == "SegmentR" + segmentsReceived[packet_number - 1].packet_pos.ToString()))
                                        {
                                            var.BackColor = Color.DeepSkyBlue;//Packet Received but ACK is corrupted
                                        }
                                    }
                                }
                            }
                        }

                        if (!corrupt_ACK)//Check corrupt ACK is false or true
                        {
                            //if it is false
                            data = new byte[3];//3 Byte long Array
                            data = Encoding.ASCII.GetBytes("ACK");//ACK is encoded to byte
                            client.Send(data, data.Length, SocketFlags.None);//Send ACK to Sender Side

                            foreach (Control var in this.gbSegmentReceived.Controls)//Checks all controls in Form
                            {
                                if (var is Label && (var.Name == "SegmentR" + segmentsReceived[packet_number - 1].packet_pos.ToString()))
                                {
                                    var.BackColor = Color.Red;//Segment Received and ACK sent :)
                                }
                            }
                        }
                    }
                    else
                    {
                        segmentsReceived[packet_number - 1].reached_dest = false; //Segment Not Received
                        segmentsReceived[packet_number - 1].packet_pos = packet_number;//Packet Position is Set

                        data = new byte[4];//4 bytes for Data
                        data = Encoding.ASCII.GetBytes("NACK");//NACK is encoded
                        client.Send(data, data.Length, SocketFlags.None);//NACK is sent to Server Side
                        for (int i = 0; i < corruptedACKs_index.Length; i++)
                        {
                            if (corruptedACKs_index[i].Index == packet_number && !corruptedACKs_index[i].Used)
                            {
                                corruptedACKs_index[i].Used = true;//Index is used 
                            }
                        }
                    }
                    client.Close();//Client Connection is closed
                }
                    newsock.Close();//Server Connection is closed

            }
            catch (Exception ex)
            {
                // MessageBox.Show(ex.Message,"Exception",MessageBoxButtons.OK,MessageBoxIcon.Error);//Exception Message is shown
            }
        }

      

        

       

       
    }
}
