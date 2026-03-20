namespace Mobiscan.Core.Utilities;

public static class FileUtils
{
    public static IEnumerable<string> EnumerateFiles(string root, params string[] extensions)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            return Array.Empty<string>();
        }

        var allowed = new HashSet<string>(extensions.Select(e => e.StartsWith('.') ? e : "." + e), StringComparer.OrdinalIgnoreCase);
        return Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(path => allowed.Count == 0 || allowed.Contains(Path.GetExtension(path)));
    }

    public static string ReadAllTextSafe(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch
        {
            return string.Empty;
        }
    }

    public static int GetLineNumber(string content, int index)
    {
        if (index <= 0)
        {
            return 1;
        }

        var line = 1;
        for (var i = 0; i < Math.Min(index, content.Length); i++)
        {
            if (content[i] == '\n')
            {
                line++;
            }
        }

        return line;
    }
}
