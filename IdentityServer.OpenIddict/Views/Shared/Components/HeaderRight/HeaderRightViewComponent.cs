using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.HeaderRight;

public class HeaderRightViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}