using System.Collections.Immutable;
using System.Security.Claims;
using IdentityServer.OpenIddict.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace IdentityServer.OpenIddict.Controllers;

public abstract class ControllerBase : Controller
{
    protected SignInManager<ApplicationUser> SignInManager { get; }
    protected UserManager<ApplicationUser> UserManager { get; }
    protected IOpenIddictApplicationManager ApplicationManager { get; }
    protected IOpenIddictAuthorizationManager AuthorizationManager { get; }
    protected IOpenIddictScopeManager ScopeManager { get; }
    // protected IOpenIddictTokenManager TokenManager => LazyServiceProvider.LazyGetRequiredService<IOpenIddictTokenManager>();
    // protected AbpOpenIddictClaimsPrincipalManager OpenIddictClaimsPrincipalManager => LazyServiceProvider.LazyGetRequiredService<AbpOpenIddictClaimsPrincipalManager>();
    // protected IAbpClaimsPrincipalFactory AbpClaimsPrincipalFactory => LazyServiceProvider.LazyGetRequiredService<IAbpClaimsPrincipalFactory>();

    protected ControllerBase(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager)
    {
        SignInManager = signInManager;
        UserManager = userManager;
        ApplicationManager = applicationManager;
        AuthorizationManager = authorizationManager;
        ScopeManager = scopeManager;
    }

    protected virtual Task<OpenIddictRequest> GetOpenIddictServerRequestAsync(HttpContext httpContext)
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("无法检索 OpenIdConnect 请求");

        return Task.FromResult(request);
    }

    protected virtual async Task<IEnumerable<string>> GetResourcesAsync(ImmutableArray<string> scopes)
    {
        var resources = new List<string>();
        if (!scopes.Any())
        {
            return resources;
        }

        await foreach (var resource in ScopeManager.ListResourcesAsync(scopes))
        {
            resources.Add(resource);
        }

        return resources;
    }
    
    protected virtual async Task<bool> HasFormValueAsync(string name)
    {
        if (Request.HasFormContentType)
        {
            var form = await Request.ReadFormAsync();
            if (!string.IsNullOrEmpty(form[name]))
            {
                return true;
            }
        }

        return false;
    }

    protected static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            // 当 claim 为 "name" 并授予 "profile" 范围时（通过调用 principal.SetScopes(...)）,
            // 允许 claims 存储在 AccessToken 和 IdentityToken 中
            case OpenIddictConstants.Claims.Name:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Profile))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Email:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Email))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Role:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Roles))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield break;
        }
    }
}