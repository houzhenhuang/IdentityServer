using IdentityServer.OpenIddict.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace IdentityServer.OpenIddict.Controllers;

[Route("connect/token")]
[IgnoreAntiforgeryToken]
[ApiExplorerSettings(IgnoreApi = true)]
public partial class TokenController : ControllerBase
{
    public TokenController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager)
        : base(signInManager, userManager, applicationManager, authorizationManager, scopeManager)
    {
    }

    [HttpGet, HttpPost, Produces("application/json")]
    public virtual async Task<IActionResult> HandleAsync()
    {
        var request = await GetOpenIddictServerRequestAsync(HttpContext);

        if (request.IsPasswordGrantType())
        {
            return await HandlePasswordAsync(request);
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            return await HandleAuthorizationCodeAsync(request);
        }

        if (request.IsRefreshTokenGrantType())
        {
            return await HandleRefreshTokenAsync(request);
        }

        if (request.IsDeviceCodeGrantType())
        {
            return await HandleDeviceCodeAsync(request);
        }

        if (request.IsClientCredentialsGrantType())
        {
            return await HandleClientCredentialsAsync(request);
        }

        // var extensionGrantsOptions = HttpContext.RequestServices.GetRequiredService<IOptions<AbpOpenIddictExtensionGrantsOptions>>();
        // var extensionTokenGrant = extensionGrantsOptions.Value.Find<ITokenExtensionGrant>(request.GrantType);
        // if (extensionTokenGrant != null)
        // {
        //     return await extensionTokenGrant.HandleAsync(new ExtensionGrantContext(HttpContext, request));
        // }

        throw new Exception($"指定的GrantType未实现:{request.GrantType}");
    }
}