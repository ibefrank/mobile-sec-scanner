namespace Mobiscan.Core.Utilities;

public static class EntropyCalculator
{
    public static double ShannonEntropy(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return 0;
        }

        var counts = new Dictionary<char, int>();
        foreach (var ch in value)
        {
            counts[ch] = counts.TryGetValue(ch, out var current) ? current + 1 : 1;
        }

        var entropy = 0d;
        var length = value.Length;
        foreach (var count in counts.Values)
        {
            var p = (double)count / length;
            entropy -= p * Math.Log(p, 2);
        }

        return entropy;
    }
}
