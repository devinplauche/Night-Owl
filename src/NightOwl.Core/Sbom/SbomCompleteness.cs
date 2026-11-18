using NightOwl.Core.Findings;

namespace NightOwl.Core.Sbom;

/// <summary>
/// Policy check behind `sbom.required-fields` in .nightowl/policy.yml: an SBOM is only as
/// useful as its least-described component, so a component missing a required field (no
/// license list, no purl) becomes a finding instead of passing silently.
/// </summary>
public static class SbomCompleteness
{
    public static readonly string[] KnownFields = ["name", "version", "ecosystem", "purl", "licenses", "locations"];

    /// <summary>The required fields this component does not carry, in the order the policy listed them.</summary>
    public static IReadOnlyList<string> MissingFields(SbomComponent component, IEnumerable<string> requiredFields)
    {
        var missing = new List<string>();
        foreach (var field in requiredFields)
        {
            var present = field.ToLowerInvariant() switch
            {
                "name" => !string.IsNullOrWhiteSpace(component.Package.Name),
                "version" => !string.IsNullOrWhiteSpace(component.Package.Version),
                "ecosystem" => !string.IsNullOrWhiteSpace(component.Package.Ecosystem),
                "purl" => !string.IsNullOrWhiteSpace(component.Package.Purl),
                "licenses" => component.Licenses.Count > 0,
                "locations" => component.FoundIn.Count > 0,
                _ => true, // Unknown names are rejected when the policy is parsed.
            };
            if (!present)
            {
                missing.Add(field.ToLowerInvariant());
            }
        }

        return missing;
    }

    /// <summary>
    /// One low-severity finding per incomplete component, naming every missing field.
    /// Syft lists the same package once per manifest that declares it; those components
    /// share a fingerprint, so duplicates are collapsed — these findings are appended
    /// after the scan's merge step and nothing downstream would dedupe them.
    /// </summary>
    public static IReadOnlyList<Finding> Findings(SoftwareBillOfMaterials sbom, IEnumerable<string> requiredFields)
    {
        var required = requiredFields.ToList();
        var findings = new List<Finding>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var component in sbom.Components)
        {
            var missing = MissingFields(component, required);
            if (missing.Count == 0)
            {
                continue;
            }

            var id = Fingerprint.ForSbomCompleteness(component.Package, missing);
            if (!seen.Add(id))
            {
                continue;
            }

            findings.Add(new Finding
            {
                Id = id,
                Category = FindingCategory.Quality,
                Severity = Severity.Low,
                RuleId = "sbom-incomplete",
                Title = $"SBOM component {component.Package.Name}@{component.Package.Version} is missing required field{(missing.Count == 1 ? "" : "s")}: {string.Join(", ", missing)}",
                Description = "The project's policy (sbom.required-fields in .nightowl/policy.yml) requires every SBOM component to carry these fields.",
                Package = component.Package,
                Location = component.FoundIn.FirstOrDefault() is { } foundIn ? new SourceLocation(foundIn) : null,
                Engines = ["policy"],
            });
        }

        return findings;
    }
}
