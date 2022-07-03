
namespace wireshark_parser.Entities;

public class Packet
{
    public int Id { get; set; }
    public int PacketNumber { get; set; }
    public string? TimeUTC { get; set; }
    public string? IPSource { get; set; }
    public string? IPDestination { get; set; }
    public string? ProtocolName { get; set; }
    public string? HTTPMethod { get; set; }

}
