using wireshark_parser.Entities;
using Dapper;
using System.Data;
using System.Data.SQLite;
using Windows.Storage;

namespace wireshark_parser;

internal class DataAccessSQLite
{
    internal static List<Packet> LoadPackets()
    {
        using IDbConnection connection = new SQLiteConnection(LoadConnectionString());

        var output = connection.Query<Packet>("select * from Packets", new DynamicParameters());
        return output.ToList();
    }

    internal static void SavePacket(Packet packet)
    {
        using IDbConnection connection = new SQLiteConnection(LoadConnectionString());

        connection.Execute("insert into Packets (PacketNumber, TimeUTC, IPSource, IPDestination, ProtocolName, HTTPMethod) " +
            "values (@PacketNumber, @TimeUTC, @IPSource, @IPDestination, @ProtocolName, @HTTPMethod)", packet);
    }

    private static string LoadConnectionString()
    {
        // Connect to DB.
        var connectionStringBuilder = new SQLiteConnectionStringBuilder
        {
            DataSource = Path.Combine(ApplicationData.Current.LocalFolder.Path) + @"Database\PcapParserDB.db"
        };

        return connectionStringBuilder.ConnectionString;
    }
}
