namespace wireshark_parser;

internal class ProtocolHelper
{
    public enum Protocol
    {
        ICMP,
        FTP,
        HTTP,
        HTTPS
    }

    /// <summary>
    /// Takes in protocol Enum and returns correct filter for that protocol in 
    /// Berkeley Packet Filter (BPF) syntax.
    /// https://www.tcpdump.org/manpages/pcap-filter.7.html
    /// </summary>
    /// <returns> Return correct filter string in BPF syntax for pcap reader device.</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    internal static string ToFilterSyntax(Protocol protocol) => protocol switch
    {
        Protocol.ICMP => "icmp",
        Protocol.FTP => "ip and tcp port 21",
        Protocol.HTTP => "ip and tcp port 80",
        Protocol.HTTPS => "ip and tcp port 443",
        _ => throw new ArgumentOutOfRangeException(nameof(protocol), $"Not expected protocol name: {protocol}"),
    };
}
