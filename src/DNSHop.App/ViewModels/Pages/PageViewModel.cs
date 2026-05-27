using DNSHop.App.Localization;
using System.ComponentModel;

namespace DNSHop.App.ViewModels.Pages;

public abstract class PageViewModel : ViewModelBase
{
    protected PageViewModel(string navKey, string titleKey)
    {
        NavKey = navKey;
        TitleKey = titleKey;
        Localization = LocalizationService.Instance;
        Localization.PropertyChanged += OnLocalizationChanged;
    }

    public string NavKey { get; }

    public string TitleKey { get; }

    public ILocalizationService Localization { get; }

    public string Title => Localization[TitleKey];

    public virtual void OnActivated() { }

    public virtual void OnDeactivated() { }

    private void OnLocalizationChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(Title));
        OnLocalizationRefresh();
    }

    protected virtual void OnLocalizationRefresh() { }
}
