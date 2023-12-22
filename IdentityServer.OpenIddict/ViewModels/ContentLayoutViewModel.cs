namespace IdentityServer.OpenIddict.ViewModels;

public class ContentLayoutViewModel
{
    public string HeaderView { get; set; } = string.Empty;
    public string ContentView { get; set; } = string.Empty;
}

public class ContentLayoutViewModel<T> : ContentLayoutViewModel
{
    public T Data { get; set; } = default!;
}