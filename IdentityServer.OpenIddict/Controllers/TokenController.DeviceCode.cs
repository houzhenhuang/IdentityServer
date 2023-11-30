using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.OpenIddict.Controllers;

public partial class TokenController : ControllerBase
{
    protected virtual async Task<IActionResult> HandleDeviceCodeAsync(OpenIddictRequest request)
    {
        return SignIn(new ClaimsPrincipal(new ClaimsIdentity()), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}