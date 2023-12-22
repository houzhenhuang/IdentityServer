using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.HeaderLeft;

public class HeaderLeftViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}