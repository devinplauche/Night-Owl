using System.Text.Json;
using System.Text.Json.Nodes;

namespace NightOwl.Cli;

/// <summary>
/// Rewrites one requirement in a composer.json, keeping the constraint style the project
/// chose: an exact pin stays exact, ^ and ~ keep their operator. Only simple constraints
/// are edited — a single version with an optional ^ or ~ prefix. Ranges, wildcards and
/// branch constraints (dev-master, *) are left to a human, as are packages the manifest
/// does not require directly: Composer has no overrides mechanism to pin a transitive
/// dependency with.
/// </summary>
internal static class ComposerManifestEditor
{
    public static string? SetRequirement(string composerJson, string package, string targetVersion)
    {
        var root = JsonNode.Parse(composerJson)?.AsObject();
        if (root is null)
        {
            return null;
        }

        foreach (var section in new[] { "require", "require-dev" })
        {
            if (root[section] is not JsonObject requirements)
            {
                continue;
            }

            var key = requirements.Select(p => p.Key)
                .FirstOrDefault(k => string.Equals(k, package, StringComparison.OrdinalIgnoreCase));
            if (key is null || requirements[key]?.GetValue<string>() is not { } constraint)
            {
                continue;
            }

            if (Retarget(constraint, targetVersion) is not { } retargeted)
            {
                return null;
            }

            requirements[key] = retargeted;
            return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n";
        }

        return null;
    }

    private static string? Retarget(string constraint, string targetVersion)
    {
        var trimmed = constraint.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        if (char.IsDigit(trimmed[0]))
        {
            // A lone version only: digits, dots and a pre-release suffix. Anything with a
            // space, comma, | or * is a range or wildcard and is left alone.
            return trimmed.All(c => char.IsDigit(c) || c is '.' or '-' or '+' or '_' || char.IsLetter(c)) ? targetVersion : null;
        }

        return trimmed[0] is '^' or '~' && Retarget(trimmed[1..].TrimStart(), targetVersion) is not null
            ? $"{trimmed[0]}{targetVersion}"
            : null;
    }
}
