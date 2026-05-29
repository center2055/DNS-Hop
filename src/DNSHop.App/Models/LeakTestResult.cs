using System;

namespace DNSHop.App.Models;

public enum LeakTestOutcome
{
    /// <summary>The active resolver matches a resolver the user applied through DNS Hop.</summary>
    Clear,

    /// <summary>The user applied a resolver in-app, but the system is using a different one.</summary>
    Override,

    /// <summary>Nothing was applied in-app, so there is no target to verify against. Not a leak.</summary>
    NotApplicable,

    /// <summary>The active system resolver could not be detected at all.</summary>
    Undetectable,
}

public sealed class LeakTestResult
{
    public required LeakTestOutcome Outcome { get; init; }

    public required DateTimeOffset CheckedAt { get; init; }

    public string? ExpectedResolver { get; init; }

    public string? ObservedResolver { get; init; }

    public string? Note { get; init; }

    /// <summary>Convenience flag kept for callers that only care about the "all clear" state.</summary>
    public bool Passed => Outcome == LeakTestOutcome.Clear;
}
