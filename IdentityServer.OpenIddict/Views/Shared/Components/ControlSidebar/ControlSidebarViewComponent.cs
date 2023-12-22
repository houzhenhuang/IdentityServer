using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.ControlSidebar;

public class ControlSidebarViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}