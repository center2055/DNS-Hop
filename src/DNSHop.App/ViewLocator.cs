using System;
using System.Diagnostics.CodeAnalysis;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using DNSHop.App.ViewModels;

namespace DNSHop.App;

[RequiresUnreferencedCode(
    "Default implementation of ViewLocator involves reflection which may be trimmed away.",
    Url = "https://docs.avaloniaui.net/docs/concepts/view-locator")]
public class ViewLocator : IDataTemplate
{
    public Control? Build(object? param)
    {
        if (param is null)
        {
            return null;
        }

        var vmTypeName = param.GetType().FullName!;
        var viewTypeName = vmTypeName
            .Replace(".ViewModels.", ".Views.", StringComparison.Ordinal)
            .Replace("ViewModel", "View", StringComparison.Ordinal);

        var type = Type.GetType(viewTypeName);

        if (type != null)
        {
            return (Control)Activator.CreateInstance(type)!;
        }

        return new TextBlock { Text = "View not found: " + viewTypeName };
    }

    public bool Match(object? data)
    {
        return data is ViewModelBase;
    }
}
