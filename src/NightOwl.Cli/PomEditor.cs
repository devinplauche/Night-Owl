using System.Text.RegularExpressions;

namespace NightOwl.Cli;

/// <summary>
/// Sets the version of one dependency in a pom.xml, preserving the file's formatting.
/// The package name is "groupId:artifactId" (OSV form) or a bare artifactId (Syft form);
/// a bare artifactId only edits when exactly one dependency carries it, because guessing
/// between groups could upgrade the wrong library. A version given as a ${property}
/// updates the property in this pom's &lt;properties&gt;; a property inherited from a
/// parent pom, a version range, and a dependency whose version is managed outside this
/// file are left to a human (null).
/// </summary>
internal static partial class PomEditor
{
    public static string? SetDependencyVersion(string pom, string package, string targetVersion)
    {
        var (group, artifact) = package.Contains(':')
            ? (package.Split(':', 2)[0], package.Split(':', 2)[1])
            : (null, package);

        var matches = DependencyBlock().Matches(pom)
            .Where(block =>
                Element(block.Groups[1].Value, "artifactId") == artifact &&
                (group is null || Element(block.Groups[1].Value, "groupId") == group))
            .ToList();
        if (matches.Count != 1)
        {
            return null; // Absent, or ambiguous without a groupId.
        }

        var match = matches[0];
        var blockText = match.Groups[1].Value;
        var versionMatch = ElementRegex("version").Match(blockText);
        if (!versionMatch.Success)
        {
            return null; // Version managed outside this pom.
        }

        var current = versionMatch.Groups[1].Value.Trim();
        if (current.StartsWith("${") && current.EndsWith('}'))
        {
            var property = current[2..^1];
            var propertyMatch = ElementRegex(Regex.Escape(property)).Match(PropertiesSection().Match(pom).Groups[1].Value);
            if (!propertyMatch.Success)
            {
                return null; // Defined in a parent pom we cannot see.
            }

            var properties = PropertiesSection().Match(pom);
            var updatedProperties = ReplaceGroup(properties.Groups[1].Value, propertyMatch, targetVersion);
            return pom[..properties.Groups[1].Index] + updatedProperties + pom[(properties.Groups[1].Index + properties.Groups[1].Length)..];
        }

        if (current.Contains('[') || current.Contains('(') || current.Contains(','))
        {
            return null; // A version range: a human picks where in the range to land.
        }

        var updatedBlock = ReplaceGroup(blockText, versionMatch, targetVersion);
        return pom[..match.Groups[1].Index] + updatedBlock + pom[(match.Groups[1].Index + match.Groups[1].Length)..];
    }

    private static string ReplaceGroup(string text, Match match, string replacement) =>
        text[..match.Groups[1].Index] + replacement + text[(match.Groups[1].Index + match.Groups[1].Length)..];

    private static string? Element(string block, string name)
    {
        var match = ElementRegex(name).Match(block);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private static Regex ElementRegex(string name) => new($@"<{name}>\s*([^<]*?)\s*</{name}>", RegexOptions.None);

    [GeneratedRegex(@"<dependency>(.*?)</dependency>", RegexOptions.Singleline)]
    private static partial Regex DependencyBlock();

    [GeneratedRegex(@"<properties>(.*?)</properties>", RegexOptions.Singleline)]
    private static partial Regex PropertiesSection();
}
