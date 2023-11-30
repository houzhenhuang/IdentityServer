using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.OpenIddict.Controllers;

public partial class TokenController : ControllerBase
{
    protected virtual async Task<IActionResult> HandlePasswordAsync(OpenIddictRequest request)
    {
        var user = await UserManager.FindByNameAsync(request.Username!);
        if (user == null)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                    "用户名或密码无效"
            }!);

            return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // 验证用户名/密码参数并确保帐户未被锁定。
        var result = await SignInManager.CheckPasswordSignInAsync(user, request.Password!, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                    "The username/password couple is invalid."
            }!);

            return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Add the claims that will be persisted in the tokens.
        identity.SetClaim(Claims.Subject, await UserManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email, await UserManager.GetEmailAsync(user))
            .SetClaim(Claims.Name, await UserManager.GetUserNameAsync(user))
            .SetClaims(Claims.Role, (await UserManager.GetRolesAsync(user)).ToImmutableArray());

        // Set the list of scopes granted to the client application.
        identity.SetScopes(new[]
        {
            Scopes.OpenId,
            Scopes.Email,
            Scopes.Profile,
            Scopes.Roles
        }.Intersect(request.GetScopes()));

        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}