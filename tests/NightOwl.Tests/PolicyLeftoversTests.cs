using NightOwl.Core.Findings;
using NightOwl.Core.Policy;
using NightOwl.Core.Sbom;
using NightOwl.Core.Triage;

namespace NightOwl.Tests;

public class PolicyLeftoversTests
{
    [Fact]
    public void Policy_parses_triage_and_sbom_sections()
    {
        var file = PolicyFile.Parse("""
            version: 1
            triage:
              accepted-risk-max-age-days: 90
            sbom:
              required-fields: [licenses, purl]
            """);

        Assert.Equal(90, file.Triage.AcceptedRiskMaxAgeDays);
        Assert.Equal(["licenses", "purl"], file.Sbom.RequiredFields);
    }

    [Theory]
    [InlineData("triage:\n  accepted-risk-max-age-days: 0\n")]
    [InlineData("sbom:\n  required-fields: [licences]\n")] // a typo must not silently pass
    public void Policy_rejects_bad_triage_and_sbom_values(string yaml) =>
        Assert.Throws<PolicyException>(() => PolicyFile.Parse(yaml));

    [Fact]
    public void Accepted_risk_without_expiry_lapses_at_the_policy_max_age()
    {
        var (store, project) = Store();
        var at = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        store.Save(project, Decision(at, expires: null), shared: true);
        var maxAge = TimeSpan.FromDays(90);

        Assert.Equal(TriageState.AcceptedRisk, StateAt(store, project, at.AddDays(89), maxAge));
        Assert.Equal(TriageState.New, StateAt(store, project, at.AddDays(91), maxAge));
        // Without the policy, the same decision would still be active.
        Assert.Equal(TriageState.AcceptedRisk, StateAt(store, project, at.AddDays(91), null));
    }

    [Fact]
    public void Explicit_expiry_wins_over_the_policy_max_age()
    {
        var (store, project) = Store();
        var at = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        store.Save(project, Decision(at, expires: at.AddDays(365)), shared: true);

        Assert.Equal(TriageState.AcceptedRisk, StateAt(store, project, at.AddDays(91), TimeSpan.FromDays(90)));
    }

    [Fact]
    public void Max_age_does_not_expire_other_states()
    {
        var (store, project) = Store();
        var at = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        store.Save(project, Decision(at, expires: null) with { State = TriageState.FalsePositive }, shared: true);

        var applied = store.Apply(project, [Finding()], at.AddDays(3650), TimeSpan.FromDays(90));
        Assert.Equal(TriageState.FalsePositive, applied[0].Triage);
    }

    [Fact]
    public void Sbom_completeness_reports_every_missing_required_field_once_per_component()
    {
        var incomplete = new SbomComponent(new PackageRef("lodash", "4.17.20", "npm"), [], []);
        var complete = new SbomComponent(new PackageRef("react", "19.0.0", "npm", "pkg:npm/react@19.0.0"), ["MIT"], ["package-lock.json"]);
        var sbom = new SoftwareBillOfMaterials([incomplete, complete], "{}");

        var findings = SbomCompleteness.Findings(sbom, ["licenses", "purl", "locations"]);

        var finding = Assert.Single(findings);
        Assert.Equal("sbom-incomplete", finding.RuleId);
        Assert.Contains("licenses, purl, locations", finding.Title);
        Assert.Equal("lodash", finding.Package?.Name);
    }

    [Fact]
    public void Sbom_completeness_is_quiet_when_nothing_is_missing()
    {
        var complete = new SbomComponent(new PackageRef("react", "19.0.0", "npm", "pkg:npm/react@19.0.0"), ["MIT"], ["package-lock.json"]);
        var sbom = new SoftwareBillOfMaterials([complete], "{}");
        Assert.Empty(SbomCompleteness.Findings(sbom, SbomCompleteness.KnownFields));
    }

    private static (TriageStore Store, string Project) Store()
    {
        var root = Directory.CreateTempSubdirectory("nightowl-policy-tests-").FullName;
        return (new TriageStore(Path.Combine(root, "home")), Directory.CreateDirectory(Path.Combine(root, "project")).FullName);
    }

    private static TriageDecision Decision(DateTimeOffset at, DateTimeOffset? expires) => new()
    {
        FindingId = "finding-1", State = TriageState.AcceptedRisk, At = at, Expires = expires, Reason = "accepted in test",
    };

    private static Finding Finding() => new()
    {
        Id = "finding-1", Category = FindingCategory.Vulnerability, Severity = Severity.High,
        RuleId = "CVE-0000", Title = "test finding",
    };

    private static TriageState StateAt(TriageStore store, string project, DateTimeOffset now, TimeSpan? maxAge) =>
        store.Apply(project, [Finding()], now, maxAge)[0].Triage;
}
