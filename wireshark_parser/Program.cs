using Fclp;
using wireshark_parser;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using static wireshark_parser.ProtocolHelper;

var builder = new ConfigurationBuilder();
BuildConfig(builder);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Build())
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateLogger();

var host = Host.CreateDefaultBuilder()
    .ConfigureServices((context, services) =>
    {
        services.AddTransient<IParser, Parser>();
    })
    .UseSerilog()
    .Build();

var parser = ActivatorUtilities.CreateInstance<Parser>(host.Services);
var argsParser = new FluentCommandLineParser<ApplicationArguments>();

string file = String.Empty;
string protocol = String.Empty;

if (args.Length == 0)
{
    Console.Write("Enter pcap file path:");
    file = Console.ReadLine();
    Console.Write("Enter protocol to handle:");
    protocol = Console.ReadLine().Trim().ToUpper();
}
else
{
    argsParser.Setup(arg => arg.PcapFile)
        .As('p', "pcap").Required();
    argsParser.Setup(arg => arg.Protocol)
        .As('f', "protocol").Required();
    argsParser.Parse(args);
    file = argsParser.Object.PcapFile;
    protocol = argsParser.Object.Protocol.Trim().ToUpper();
}

var isProtocol = Enum.GetNames(typeof(Protocol)).Contains(protocol);

if (!isProtocol)
{
    Log.Logger.Error("Incorrect protocol value input.");
}
if (File.Exists(file))
{
    Parser.Protocol = protocol;
    parser.Parse(file, protocol);
    Log.Logger.Information("Saved {count} packets to database.", DataAccessSQLite.CountPackets());
}
else
{
    Log.Logger.Error("Error with input.");
}

static void BuildConfig(IConfigurationBuilder builder)
{
    builder.SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json",
        optional: true)
        .AddEnvironmentVariables();
}