using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface IDependencyScanner
{
    Task<IReadOnlyList<Finding>> ScanAsync(ScanContext context, CancellationToken cancellationToken);
}
