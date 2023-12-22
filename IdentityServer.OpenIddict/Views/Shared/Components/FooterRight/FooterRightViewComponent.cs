using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.FooterRight;

public class FooterRightViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}