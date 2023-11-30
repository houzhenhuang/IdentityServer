using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.OpenIddict.Controllers;

public partial class TokenController : ControllerBase
{
    protected virtual async Task<IActionResult> HandleClientCredentialsAsync(OpenIddictRequest request)
    {
        // 注意：客户端凭据由 OpenIddict 自动验证：
        // 如果 client_id 或 client_secret 无效，则不会调用此操作。
        var application = await ApplicationManager.FindByClientIdAsync(request.ClientId!) ??
                          throw new InvalidOperationException($"找不到客户端Id为{request.ClientId}的应用");

        // 创建一个新的ClaimsIdentity，其中包含将用于创建id_token、token 或 code 的声明。
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

        // 使用 client_id 作为 subject identifier。
        identity.SetClaim(Claims.Subject, await ApplicationManager.GetClientIdAsync(application));
        identity.SetClaim(Claims.Name, await ApplicationManager.GetDisplayNameAsync(application));

        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}