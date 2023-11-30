using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.OpenIddict.Controllers;

public partial class TokenController
{
    protected virtual async Task<IActionResult> HandleAuthorizationCodeAsync(OpenIddictRequest request)
    {
        // 检索存储在 authorization code/refresh token 中的 claims principal。
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // 检索与 authorization code/refresh token 对应的用户配置文件
        var user = await UserManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject)!);
        if (user is null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                }!));
        }

        // 确保仍然允许用户登录。
        if (!await SignInManager.CanSignInAsync(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                }!));
        }

        var identity = new ClaimsIdentity(result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // 覆盖 principal 中存在的 user claims，以防它们自颁发 authorization code/refresh token 以来发生更改。
        identity.SetClaim(Claims.Subject, await UserManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email, await UserManager.GetEmailAsync(user))
            .SetClaim(Claims.Name, await UserManager.GetUserNameAsync(user))
            .SetClaims(Claims.Role, (await UserManager.GetRolesAsync(user)).ToImmutableArray());

        identity.SetDestinations(GetDestinations);

        // 返回 SignInResult 将要求 OpenIddict 颁发适当的 access/identity tokens.
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}