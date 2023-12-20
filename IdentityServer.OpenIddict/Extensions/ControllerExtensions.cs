using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Extensions;

public static class ControllerExtensions
{
    /// <summary>
    /// 创建 <see cref="LocalRedirectResult"/> 对象，重定向到指定的本地 localUrl
    /// </summary>
    /// <param name="controller"></param>
    /// <param name="localUrl">要重定向到的本地URL。</param>
    /// <param name="escapeUrl">是否转义url。</param>
    public static ActionResult LocalRedirect(this Controller controller, string localUrl, bool escapeUrl)
    {
        if (!escapeUrl)
        {
            return controller.LocalRedirect(localUrl);
        }

        return controller.LocalRedirect(localUrl.ToUriComponents());
    }
}