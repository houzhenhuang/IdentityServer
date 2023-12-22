using X.PagedList.Web.Common;

namespace IdentityServer.OpenIddict.Models.Paged;

public class PagedListRenderOptionsConfigure
{
    public static readonly PagedListRenderOptions Default = new PagedListRenderOptions
    {
        DisplayLinkToFirstPage = PagedListDisplayMode.Always,
        LinkToFirstPageFormat = "首页",
        DisplayLinkToNextPage = PagedListDisplayMode.Always,
        LinkToNextPageFormat = "下一页",
        DisplayLinkToPreviousPage = PagedListDisplayMode.Always,
        LinkToPreviousPageFormat = "上一页",
        DisplayLinkToLastPage = PagedListDisplayMode.Always,
        LinkToLastPageFormat = "末页",
        MaximumPageNumbersToDisplay = 5,
        DisplayItemSliceAndTotal = false
    };
}