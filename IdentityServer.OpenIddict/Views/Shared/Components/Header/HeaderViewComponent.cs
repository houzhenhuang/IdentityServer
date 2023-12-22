using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.Header;

public class HeaderViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}