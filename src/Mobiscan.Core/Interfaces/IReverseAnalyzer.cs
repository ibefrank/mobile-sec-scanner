using Mobiscan.Core.Models;

namespace Mobiscan.Core.Interfaces;

public interface IReverseAnalyzer
{
    Task<IReadOnlyList<Finding>> ScanApkAsync(ScanContext context, string apkPath, CancellationToken cancellationToken);
}
