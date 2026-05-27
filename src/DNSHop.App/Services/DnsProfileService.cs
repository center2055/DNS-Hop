using DNSHop.App.Localization;
using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DNSHop.App.Services;

internal sealed class DnsProfileService
{
    private static readonly BuiltInProfileSeed[] Seeds =
    [
        new("cloudflare", "Profiles.BuiltIn.Cloudflare", "Profiles.BuiltIn.CloudflareDescription",
            "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
            "https://cloudflare-dns.com/dns-query", DnsProtocol.Doh),

        new("quad9", "Profiles.BuiltIn.Quad9", "Profiles.BuiltIn.Quad9Description",
            "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
            "https://dns.quad9.net/dns-query", DnsProtocol.Doh),

        new("adguard-family", "Profiles.BuiltIn.AdGuardFamily", "Profiles.BuiltIn.AdGuardFamilyDescription",
            "94.140.14.15", "94.140.15.16", "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff",
            "https://family.adguard-dns.com/dns-query", DnsProtocol.Doh),

        new("mullvad", "Profiles.BuiltIn.Mullvad", "Profiles.BuiltIn.MullvadDescription",
            "194.242.2.2", "194.242.2.3", "2a07:e340::2", "2a07:e340::3",
            "https://dns.mullvad.net/dns-query", DnsProtocol.Doh),

        new("google", "Profiles.BuiltIn.Google", "Profiles.BuiltIn.GoogleDescription",
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
            "https://dns.google/dns-query", DnsProtocol.Doh),
    ];

    public IReadOnlyList<DnsProfile> GetBuiltIns(ILocalizationService localization)
    {
        return Seeds.Select(seed => new DnsProfile
        {
            Id = "builtin:" + seed.Key,
            Name = localization[seed.NameKey],
            Description = localization[seed.DescriptionKey],
            PreferredIPv4 = seed.PrefV4,
            AlternateIPv4 = seed.AltV4,
            PreferredIPv6 = seed.PrefV6,
            AlternateIPv6 = seed.AltV6,
            EncryptedEndpoint = seed.Encrypted,
            EncryptedProtocol = seed.Protocol,
            IsBuiltIn = true,
            BuiltInKey = seed.Key,
        }).ToList();
    }

    public DnsProfile? FindById(IEnumerable<DnsProfile> profiles, string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        return profiles.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.Ordinal));
    }

    private sealed record BuiltInProfileSeed(
        string Key,
        string NameKey,
        string DescriptionKey,
        string PrefV4,
        string AltV4,
        string PrefV6,
        string AltV6,
        string Encrypted,
        DnsProtocol Protocol);
}
