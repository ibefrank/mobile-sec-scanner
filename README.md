# Mobiscan

Mobiscan is a cross-platform C# command-line security tool that scans mobile applications for vulnerabilities using static analysis, dependency scanning, secret detection, configuration analysis, and APK reverse analysis. It is designed for developers and DevSecOps pipelines with fast scans, clear explanations, and optional automated fixes.

## Features
- Static analysis for Android and iOS projects
- Dependency vulnerability scanning against a local CVE database
- Secret detection using regex patterns and entropy
- Reverse analysis of APK files
- Auto-fix suggestions and optional automatic remediation
- Real-time file watching during development
- CI/CD integration with security fail thresholds
- Plugin-based rule system
- Reports in CLI, JSON, and HTML formats

## Requirements
- .NET 8 SDK and  above
- Windows, macOS, or Linux

## Installation
Build from source:

```bash
# From the repo root
 dotnet build
```

Run the CLI:

```bash
dotnet run --project src/Mobiscan.CLI -- scan ./app
```

## Usage

Scan a project:

```bash
mobiscan scan ./app
```

Scan with platform selection:

```bash
mobiscan scan ./app --platform android
```

Scan an APK:

```bash
mobiscan scan ./app --apk app.apk
```

Generate JSON or HTML reports:

```bash
mobiscan scan ./app --format json --output report.json
mobiscan scan ./app --format html --output report.html
```

Fail CI/CD pipelines on severity:

```bash
mobiscan scan ./app --fail-on high
```

Run dependency audit only:

```bash
mobiscan audit ./app
```

Watch mode:

```bash
mobiscan watch ./app
```

Apply fixes:

```bash
mobiscan fix ./app
mobiscan fix ./app --issue ANDROID_DEBUG_ENABLED
```

List rules:

```bash
mobiscan rules
```

Version:

```bash
mobiscan version
```

## Example Output

```
# Mobiscan Security Scan

3 vulnerabilities detected

[HIGH] Hardcoded API Key
File: ApiService.kt:42

Explanation:
API keys embedded in mobile apps can be extracted by attackers.

Recommended Fix:
Move the API key to a backend service or secure environment variable.
```

## Rules
Rules are defined in JSON files inside `rules/`. Example:

```json
{
  "id": "ANDROID_DEBUG_ENABLED",
  "severity": "Medium",
  "pattern": "android:debuggable=\"true\"",
  "description": "Debug mode should not be enabled in production builds",
  "fix": "set_debuggable_false"
}
```

You can add new rules by editing `rules/android_rules.json` and `rules/ios_rules.json` or by adding new rule files.

## Plugins
Plugins are .NET assemblies placed inside `plugins/`. They can provide:
- New analyzers
- New rule providers
- New fix handlers

Implement `Mobiscan.Core.Interfaces.IPlugin` and call `registry.AddAnalyzer`, `registry.AddRuleProvider`, or `registry.AddFixProvider` in `Register`.

## Project Structure

```
mobiscan/
  src/
    Mobiscan.CLI
    Mobiscan.Core
    Mobiscan.ScanEngine
    Mobiscan.RuleEngine
    Mobiscan.Analyzers.Android
    Mobiscan.Analyzers.iOS
    Mobiscan.DependencyScanner
    Mobiscan.SecretScanner
    Mobiscan.ReverseAnalyzer
    Mobiscan.FixEngine
    Mobiscan.Reporting
    Mobiscan.WatchMode
  rules/
  cve/
  plugins/
  tests/
  docs/
```

## Notes
- The vulnerability database is stored locally in `cve/vulnerability_database.json`.
- Auto-fix creates backups with a `.bak.YYYYMMDDHHMMSS` suffix.

## License
This project is open source and ready for your license of choice.
