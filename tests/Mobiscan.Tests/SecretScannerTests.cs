using Mobiscan.Core.Models;
using Mobiscan.SecretScanner;

namespace Mobiscan.Tests;

public class SecretScannerTests
{
    [Fact]
    public async Task Finds_Aws_Access_Key()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var filePath = Path.Combine(tempDir, "secrets.kt");
        await File.WriteAllTextAsync(filePath, "val key = \"AKIA1234567890ABCDE1\"");

        var scanner = new SecretScannerService();
        var context = new ScanContext { Options = new ScanOptions { TargetPath = tempDir } };
        var findings = await scanner.ScanAsync(context, CancellationToken.None);

        Assert.Contains(findings, f => f.Id == "AWS_ACCESS_KEY");
    }
}
