using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.FooterLeft;

public class FooterLeftViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}