using Mobiscan.Core.Models;

namespace Mobiscan.Core.Utilities;

public static class SeverityParser
{
    public static Severity? TryParse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return Enum.TryParse<Severity>(value, true, out var parsed) ? parsed : null;
    }
}
