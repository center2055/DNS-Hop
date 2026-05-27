using System;

namespace DNSHop.App.Models;

public sealed class LeakTestResult
{
    public required bool Passed { get; init; }

    public required DateTimeOffset CheckedAt { get; init; }

    public string? ExpectedResolver { get; init; }

    public string? ObservedResolver { get; init; }

    public string? Note { get; init; }
}
