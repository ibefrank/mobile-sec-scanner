using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface IAnalyzer
{
    string Name { get; }
    Platform Platform { get; }
    Task<IReadOnlyList<Finding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken);
}
