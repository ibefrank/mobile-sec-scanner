using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface ISecretScanner
{
    Task<IReadOnlyList<Finding>> ScanAsync(ScanContext context, CancellationToken cancellationToken);
}
