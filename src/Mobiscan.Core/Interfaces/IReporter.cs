using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface IReporter
{
    string Name { get; }
    Task WriteAsync(ScanResult result, Stream output, CancellationToken cancellationToken);
}
