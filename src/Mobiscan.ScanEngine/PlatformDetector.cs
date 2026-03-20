using Mobiscan.Core.Models;

namespace Mobiscan.ScanEngine;

public static class PlatformDetector
{
    public static Platform Detect(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return Platform.Any;
        }

        var hasAndroid = File.Exists(Path.Combine(path, "AndroidManifest.xml"))
            || Directory.EnumerateFiles(path, "build.gradle", SearchOption.AllDirectories).Any()
            || Directory.EnumerateFiles(path, "*.apk", SearchOption.AllDirectories).Any();

        var hasIos = File.Exists(Path.Combine(path, "Info.plist"))
            || Directory.EnumerateFiles(path, "Podfile", SearchOption.AllDirectories).Any()
            || Directory.EnumerateFiles(path, "*.xcodeproj", SearchOption.AllDirectories).Any();

        if (hasAndroid && !hasIos)
        {
            return Platform.Android;
        }

        if (hasIos && !hasAndroid)
        {
            return Platform.iOS;
        }

        return Platform.Any;
    }
}
