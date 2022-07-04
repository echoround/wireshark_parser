using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using SerilogTimings;
using static wireshark_parser.ProtocolHelper;

namespace wireshark_parser;

internal class Parser : IParser
{
    private readonly ILogger<Parser> _log;
    private readonly IConfiguration _config;
    private static ICaptureDevice? _device;
    private static int _packetIndex = 0;
    private static List<Entities.Packet> _packets = new();
    public static string? Protocol { get; set; }

    public Parser(ILogger<Parser> log, IConfiguration config)
    {
        _log = log;
        _config = config;
    }

    /// <summary>
    /// Uses SharpPcap to parse the pcap file with an offline pcap reader device. Event handles parsing of the packets.
    /// Extracts metadata from the packets and saves the data to DB after pcap file is read.
    /// </summary>
    internal void Parse(string pcapFile, string protocol)
    {
        // For logging execution time.
        using (Operation.Time("Parsing packets and storing to DB from {pcapFile}", pcapFile))
        {
            try
            {
                // Get an offline device for reading pcap.
                _device = new CaptureFileReaderDevice(pcapFile);
                // Open the device.
                _device.Open();
            }
            catch (Exception e)
            {
                _log.LogError(e, "Error opening device {pcapFile}", pcapFile);
                return;
            }

            // Register our handler function to the 'packet arrival' event.
            _device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Since we need certain types of protocols, I am prefiltering the data with a BPF filter based on
            // the string protocol input,which hopefully leaves only packets of the target protocol. Filtering is based on
            // ports that the protocols use. For example, filter "ftp" should leave only packets of FTP protocol.
            var protocolEnum = (Protocol)Enum.Parse(typeof(Protocol), protocol.Trim(), true);
            _device.Filter = ToFilterSyntax(protocolEnum);

            _log.LogInformation("Parsing file: '{pcapFile}'", pcapFile);
            // Start capture of packets offline. Method will return when EOF reached.
            _device.Capture();
            // Close the pcap device.
            _device.Close();

            _log.LogInformation("-- End of file reached. Read {packetIndex} packets.", _packetIndex);

            foreach (var packet in _packets)
            {
                DataAccessSQLite.SavePacket(packet);
                _log.LogInformation("Saved packet {PacketNumber}", packet.PacketNumber.ToString());
            }
        }
    }

    /// <summary>
    /// Gets the time, src ip, src port, dst ip and dst port
    /// for each packet in the filtered pcap reader, where applicable. Saves to list for adding to DB at the end.
    /// </summary>
    private void device_OnPacketArrival(object sender, PacketCapture e)
    {
        _packetIndex++;

        var time = e.Header.Timeval.Date.ToUniversalTime().ToString() + " GMT";
        var rawPacket = e.GetPacket();
        var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var tcpPacket = packet.Extract<TcpPacket>();
              
        if (tcpPacket != null)
        {
            var ipPacket = (IPPacket)tcpPacket.ParentPacket;
            var srcIp = ipPacket.SourceAddress.ToString();
            var dstIp = ipPacket.DestinationAddress.ToString();
            var srcPort = tcpPacket.SourcePort;
            var dstPort = tcpPacket.DestinationPort;

            var tempPacket = new Entities.Packet()
            {
                PacketNumber = _packetIndex,
                TimeUTC = time,
                IPSource = srcIp,
                IPDestination = dstIp,
                // This feels wrong, but must leave for now.
                ProtocolName = Protocol,
                // Placeholder- need to perform some regex on the payload or otherwise for this.
                HTTPMethod = "httpmethod"
            };

            // Add each Packet to list for adding to DB at the end.
            _packets.Add(tempPacket);

            _log.LogInformation("----------------");
            _log.LogInformation("{protocol} // {time} // " +
                "{srcIp}:{srcPort} -> {dstIp}:{dstPort} Packet index: {packetIndex}", Protocol,
                time, srcIp, srcPort, dstIp, dstPort, _packetIndex);
        }
    }
}
