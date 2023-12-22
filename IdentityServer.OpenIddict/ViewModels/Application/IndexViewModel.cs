using X.PagedList;

namespace IdentityServer.OpenIddict.ViewModels.Application;

public class IndexViewModel : BasePagedList<OpenIdApplicationEntry>
{
    public IList<OpenIdApplicationEntry> Applications { get; }

    public IndexViewModel(
        IList<OpenIdApplicationEntry> applications,
        int pageNumber,
        int pageSize,
        int totalCount)
        : base(pageNumber, pageSize, totalCount)
    {
        Applications = applications;
    }
}

public class OpenIdApplicationEntry
{
    public string DisplayName { get; set; }
    public string Id { get; set; }
    public bool IsChecked { get; set; }
}