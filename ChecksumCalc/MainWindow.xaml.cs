using System;
using System.Text;
using System.Windows;
using PcapDotNet;
using PcapDotNet.Packets;
using System.Linq;

namespace ChecksumCalc
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private long ByteSum(string dataToCalculate)
        {
            byte[] header = StringToByteArray(dataToCalculate);
            int length = header.Length;

            if (length % 2 > 0)
            {
                Array.Resize<byte>(ref header, length + 1);
                length = header.Length;
            }

            ushort word16;
            long sum = 0;
            for (int i = 0; i < length; i += 2)
            {
                word16 = (ushort)(((header[i] << 8) & 0xFF00)
                + (header[i + 1] & 0xFF));
                sum += (long)word16;
            }
            return sum;
        }

        private long FinalizeChecksum(long sum, bool isUdp)
        {
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            sum = ~sum;
            sum = (sum & 0xFFFF);

            if (isUdp)
            {
                if (sum == 0)
                {
                    sum = 0xFFFF;
                }
            }

            return sum;
        }
        private string CalculateChecksum(Packet packet, bool isIPv6, bool isUdp)
        {
            long psuedoHeaderChecksum = 0;
            string oldData;
            var checksumOffset = isUdp ? 6 : 16;
            var checksumlocation = checksumOffset * 2;

            if (isIPv6)
            {
                // NOT TESTED
                psuedoHeaderChecksum = ByteSum(packet.Ethernet.IpV6.Source.ToValue().ToString("X8")) +
                                        ByteSum(packet.Ethernet.IpV6.CurrentDestination.ToValue().ToString("X8")) +
                                        ByteSum("00" + packet.Ethernet.IpV6.NextHeader.ToString("X"));
                if (isUdp)
                {
                    psuedoHeaderChecksum += ByteSum(packet.Ethernet.IpV6.Udp.Length.ToString("X4"));
                    // Set existing checksum to 0
                    oldData = packet.Ethernet.IpV6.Udp.Subsegment(0, packet.Ethernet.IpV6.Udp.Length).ToHexadecimalString();
                }
                else
                {
                    psuedoHeaderChecksum += ByteSum(packet.Ethernet.IpV6.Tcp.Length.ToString("X4"));
                    // Set existing checksum to 0
                    oldData = packet.Ethernet.IpV6.Tcp.Subsegment(0, packet.Ethernet.IpV6.Tcp.Length).ToHexadecimalString();
                }
            }
            else
            {
                psuedoHeaderChecksum = ByteSum(packet.Ethernet.IpV4.Source.ToValue().ToString("X8")) +
                        ByteSum(packet.Ethernet.IpV4.Destination.ToValue().ToString("X8")) +
                        ByteSum("00" + packet.Ethernet.IpV4.Protocol.ToString("X"));
                if (isUdp)
                {
                    psuedoHeaderChecksum += ByteSum(packet.Ethernet.IpV4.Udp.Length.ToString("X4"));
                    // Set existing checksum to 0
                    oldData = packet.Ethernet.IpV4.Udp.Subsegment(0, packet.Ethernet.IpV4.Udp.Length).ToHexadecimalString();
                }
                else
                {
                    psuedoHeaderChecksum += ByteSum(packet.Ethernet.IpV4.Tcp.Length.ToString("X4"));
                    // Set existing checksum to 0
                    oldData = packet.Ethernet.IpV4.Tcp.Subsegment(0, packet.Ethernet.IpV4.Tcp.Length).ToHexadecimalString();
                }
            }

            var oldDataArray = oldData.ToCharArray();
            oldDataArray[checksumlocation] = '0';
            oldDataArray[checksumlocation+1] = '0';
            oldDataArray[checksumlocation+2] = '0';
            oldDataArray[checksumlocation+3] = '0';

            var calcChecksum = psuedoHeaderChecksum + ByteSum(new string(oldDataArray));

            return FinalizeChecksum(calcChecksum, isUdp).ToString("X4");
        }

        private void HexData_GotFocus(object sender, RoutedEventArgs e)
        {
            HexData.Text = String.Empty;
            Checksum.Text = "0";
            ChecksumActual.Text = "0";
        }

        private void Calculate_Click(object sender, RoutedEventArgs e)
        {
            var sanitizedInput = new string(HexData.Text.Where(x => !Char.IsWhiteSpace(x)).ToArray());
            var packet = Packet.FromHexadecimalString(sanitizedInput, DateTime.Now, DataLinkKind.Ethernet);
            var ipProto = packet.Ethernet.EtherType;
            var isIPv6 = packet.Ethernet.EtherType == PcapDotNet.Packets.Ethernet.EthernetType.IpV6;
            var transportProto = isIPv6 ? packet.Ethernet.IpV6.NextHeader : packet.Ethernet.IpV4.Protocol;
            var isUdp = transportProto == PcapDotNet.Packets.IpV4.IpV4Protocol.Udp;
            var knownPacket = false;
            ushort transportChecksum = 0;

            if (ipProto == PcapDotNet.Packets.Ethernet.EthernetType.IpV4)
            {
                if (transportProto == PcapDotNet.Packets.IpV4.IpV4Protocol.Tcp)
                {
                    transportChecksum = packet.Ethernet.IpV4.Tcp.Checksum;
                    knownPacket = true;
                }
                else if (transportProto == PcapDotNet.Packets.IpV4.IpV4Protocol.Udp)
                {
                    transportChecksum = packet.Ethernet.IpV4.Udp.Checksum;
                    knownPacket = true;
                }
            }
            else if (ipProto == PcapDotNet.Packets.Ethernet.EthernetType.IpV6)
            {
                if (transportProto == PcapDotNet.Packets.IpV4.IpV4Protocol.Tcp)
                {
                    transportChecksum = packet.Ethernet.IpV6.Tcp.Checksum;
                    knownPacket = true;
                }
                else if (transportProto == PcapDotNet.Packets.IpV4.IpV4Protocol.Udp)
                {
                    transportChecksum = packet.Ethernet.IpV6.Udp.Checksum;
                    knownPacket = true;
                }
            }

            if (knownPacket == true)
            {
                PacketInfo.Content = packet.DataLink.Kind.ToString() + ipProto + transportProto;

                Checksum.Text = CalculateChecksum(packet, isIPv6, isUdp);
                ChecksumActual.Text = transportChecksum.ToString("X4");
            }
        }

        private void Sanitize_Click(object sender, RoutedEventArgs e)
        {
            var inputChar = HexData.Text.ToCharArray();
            var newArr = new char[inputChar.Length];
            var tickLoc = 8;

            var lineIndex = 0;
            int currChar = 0;
            int destChar = 0;
            while (currChar < inputChar.Length)
            {
                if (inputChar[lineIndex*86 + tickLoc] == '`')
                {
                    int lineLength = Math.Min(86, inputChar.Length - lineIndex * 86);
                    currChar += 19;
                    for (var i = 19; i < lineLength; i++)
                    {
                        int currLineChar = lineIndex * 86 + i;
                        if ((inputChar[currLineChar - 1] == '\r') && (inputChar[currLineChar] == '\n'))
                        {
                            lineIndex++;
                        }
                        else if ((i < 66) && inputChar[currLineChar] != ' ' && inputChar[currLineChar] != '-')
                        {
                            newArr[destChar++] = inputChar[currLineChar];
                        }
                        currChar++;
                    }
                }
                else
                {
                    newArr = inputChar;
                    break;
                }
                Array.Resize<char>(ref newArr, destChar);
            }
            HexData.Text = new string(newArr.Where(x => !Char.IsWhiteSpace(x)).ToArray());

        }
    }
}
