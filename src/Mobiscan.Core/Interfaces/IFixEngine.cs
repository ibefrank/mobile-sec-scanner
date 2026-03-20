using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface IFixEngine
{
    Task<IReadOnlyList<FixResult>> ApplyFixesAsync(ScanContext context, IReadOnlyList<Finding> findings, CancellationToken cancellationToken);
    Task<IReadOnlyList<FixResult>> ApplyFixAsync(ScanContext context, string issueId, CancellationToken cancellationToken);
}
