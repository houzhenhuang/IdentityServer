using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.SidebarUserPanel;

public class SidebarUserPanelViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}