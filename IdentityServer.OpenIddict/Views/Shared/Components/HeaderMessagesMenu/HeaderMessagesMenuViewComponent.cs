using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Views.Shared.Components.HeaderMessagesMenu;

public class HeaderMessagesMenuViewComponent : ViewComponent
{
    public IViewComponentResult Invoke() => View();
}