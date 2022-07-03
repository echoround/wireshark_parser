/*Seadista kaks serverit (võib olla Azure, AWS või muu oma valitud virtualiseerimise keskkond).
Genereeri nende serverite vahel võrguliiklust ja salvesta see Wiresharkiga.
Võrguliiklus peab sisaldama järgmisi protokolle: ICMP, FTP, HTTP, HTTPS.
Kirjuta Pythonis või teises vabalt valitud keeles Wiresharki faili parser mis:
eraldab võrguliikluse dump failist ainult ette antud protokolli paketid.
salvestab paketi metadata sqlite andmebaasi.
paketi metadata mis on vaja andmebaasi salvestada: paketi number, UTC kellaaeg,  source ip aadress, destination ip aadress, protokolli nimi (HTTP ja HTTPS protokolli puhul ka protokolli meetod (GET,POST jne))
Wireshark dumpi faili ja otsitava protokolli valiku peaks tegema käsurea parameetriga.
Skript peab logima nii INFO kui ka ERROR striimi sekundi täpsusega.*/

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

argsParser.Setup(arg => arg.PcapFile)
 .As('p', "pcap")
 .Required();

argsParser.Setup(arg => arg.Protocol)
 .As('f', "protocol")
 .Required();

var result = argsParser.Parse(args);

var file = argsParser.Object.PcapFile;
var protocol = argsParser.Object.Protocol.Trim().ToUpper();

var isProtocol = Enum.GetNames(typeof(Protocol)).Contains(protocol);

if (!isProtocol)
{
    Log.Logger.Error("Incorrect protocol value input.");
}

if (!result.HasErrors && File.Exists(file))
{
    Log.Logger.Information(file);
    Parser.Protocol = protocol;
    parser.Parse(file, protocol);

    foreach (var packet in DataAccessSQLite.LoadPackets())
    {
        Console.WriteLine(packet.PacketNumber);
        Console.WriteLine(packet.IPDestination);
        
    }
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