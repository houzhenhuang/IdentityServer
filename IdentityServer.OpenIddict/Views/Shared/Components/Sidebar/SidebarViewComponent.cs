using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.Sidebar;

public class SidebarViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}