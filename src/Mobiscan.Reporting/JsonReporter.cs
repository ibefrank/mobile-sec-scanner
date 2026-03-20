using System.Text.Json;
using Mobiscan.Core.Interfaces;
using Mobiscan.Core.Models;

namespace Mobiscan.Reporting;

public sealed class JsonReporter : IReporter
{
    public string Name => "json";

    public async Task WriteAsync(ScanResult result, Stream output, CancellationToken cancellationToken)
    {
        await JsonSerializer.SerializeAsync(output, result, new JsonSerializerOptions
        {
            WriteIndented = true
        }, cancellationToken);
    }
}
