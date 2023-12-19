namespace IdentityServer.OpenIddict.ViewModels.Application;

public class IndexViewModel
{
    public IList<OpenIdApplicationEntry> Applications { get; } = new List<OpenIdApplicationEntry>();
}

public class OpenIdApplicationEntry
{
    public string DisplayName { get; set; }
    public string Id { get; set; }
    public bool IsChecked { get; set; }
}