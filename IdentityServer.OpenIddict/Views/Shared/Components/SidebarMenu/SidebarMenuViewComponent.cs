using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.SidebarMenu;

public class SidebarMenuViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}