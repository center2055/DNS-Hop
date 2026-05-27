using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace DNSHop.App.Localization;

public interface ILocalizationService : INotifyPropertyChanged
{
    string this[string key] { get; }

    string CurrentCulture { get; }

    IReadOnlyList<LanguageDescriptor> AvailableLanguages { get; }

    void SetCulture(string culture);

    event EventHandler? CultureChanged;
}

public sealed record LanguageDescriptor(string Culture, string NativeName, string EnglishName);
