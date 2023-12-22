using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.Footer;

public class FooterViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}