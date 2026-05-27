using Avalonia.Data;
using Avalonia.Markup.Xaml;
using System;

namespace DNSHop.App.Localization;

public sealed class LocalizeExtension : MarkupExtension
{
    public LocalizeExtension()
    {
    }

    public LocalizeExtension(string key)
    {
        Key = key;
    }

    public string Key { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        return new Binding($"[{Key}]")
        {
            Source = LocalizationService.Instance,
            Mode = BindingMode.OneWay,
            FallbackValue = Key,
        };
    }
}
