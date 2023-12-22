using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.SidebarBrand;

public class SidebarBrandViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}