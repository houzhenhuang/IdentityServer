using IdentityServer.OpenIddict.Extensions;
using IdentityServer.OpenIddict.ViewModels.Application;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace IdentityServer.OpenIddict.Controllers;

[Authorize(AuthenticationSchemes = "Identity.Application")]
public class ApplicationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    public ApplicationController(IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var vm = new IndexViewModel();

        await foreach (var application in _applicationManager.ListAsync(20, 0))
        {
            vm.Applications.Add(new OpenIdApplicationEntry
            {
                Id = (await _applicationManager.GetIdAsync(application))!,
                DisplayName = (await _applicationManager.GetDisplayNameAsync(application))!
            });
        }

        return View("Index", vm);
    }

    [HttpGet]
    public async Task<IActionResult> Create(string? returnUrl = null)
    {
        var vm = new CreateViewModel();

        await foreach (var scope in _scopeManager.ListAsync())
        {
            vm.ScopeEntries.Add(new CreateViewModel.ScopeEntry
            {
                Name = (await _scopeManager.GetNameAsync(scope))!
            });
        }

        ViewData["ReturnUrl"] = returnUrl;

        return View(vm);
    }


    [HttpPost]
    public async Task<IActionResult> Create(CreateViewModel vm, string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(vm.ClientSecret) &&
            string.Equals(vm.Type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError(nameof(vm.ClientSecret), "不能为 Public Client 应用程序设置客户端密钥。");
        }
        else if (string.IsNullOrEmpty(vm.ClientSecret) &&
                 string.Equals(vm.Type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError(nameof(vm.ClientSecret), "Confidential Client 应用程序需要客户端密钥。");
        }

        if (!string.IsNullOrEmpty(vm.ClientId) && await _applicationManager.FindByClientIdAsync(vm.ClientId) != null)
        {
            ModelState.AddModelError(nameof(vm.ClientId), "客户端Id已被另一个应用程序占用。");
        }

        if (!ModelState.IsValid)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(vm);
        }

        var settings = new OpenIdApplicationSettings()
        {
            AllowAuthorizationCodeFlow = vm.AllowAuthorizationCodeFlow,
            AllowClientCredentialsFlow = vm.AllowClientCredentialsFlow,
            AllowHybridFlow = vm.AllowHybridFlow,
            AllowImplicitFlow = vm.AllowImplicitFlow,
            AllowIntrospectionEndpoint = vm.AllowIntrospectionEndpoint,
            AllowLogoutEndpoint = vm.AllowLogoutEndpoint,
            AllowPasswordFlow = vm.AllowPasswordFlow,
            AllowRefreshTokenFlow = vm.AllowRefreshTokenFlow,
            AllowRevocationEndpoint = vm.AllowRevocationEndpoint,
            ClientId = vm.ClientId,
            ClientSecret = vm.ClientSecret,
            ConsentType = vm.ConsentType,
            DisplayName = vm.DisplayName,
            PostLogoutRedirectUris = vm.PostLogoutRedirectUris,
            RedirectUris = vm.RedirectUris,
            Roles = vm.RoleEntries.Where(x => x.Selected).Select(x => x.Name).ToArray(),
            Scopes = vm.ScopeEntries.Where(x => x.Selected).Select(x => x.Name).ToArray(),
            Type = vm.Type,
            RequireProofKeyForCodeExchange = vm.RequireProofKeyForCodeExchange
        };

        await _applicationManager.UpdateDescriptorFromSettings(settings);

        if (string.IsNullOrEmpty(returnUrl))
        {
            return RedirectToAction(nameof(Index));
        }

        return this.LocalRedirect(returnUrl, true);
    }

    [HttpGet]
    public async Task<IActionResult> Edit(string id, string? returnUrl = null)
    {
        var application = await _applicationManager.FindByIdAsync(id);
        if (application == null)
        {
            return NotFound();
        }

        ValueTask<bool> HasPermissionAsync(string permission) => _applicationManager.HasPermissionAsync(application, permission);
        ValueTask<bool> HasRequirementAsync(string requirement) => _applicationManager.HasRequirementAsync(application, requirement);

        var vm = new EditViewModel()
        {
            AllowAuthorizationCodeFlow = await HasPermissionAsync(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode) &&
                                         await HasPermissionAsync(OpenIddictConstants.Permissions.ResponseTypes.Code),

            AllowClientCredentialsFlow = await HasPermissionAsync(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials),

            // Note: 混合流没有专用的grant_type，而是被视为授权代码和隐式授权的组合。因此，为了确定是否启用混合流，必须启用授权代码授予和隐式授予。
            AllowHybridFlow = await HasPermissionAsync(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode) &&
                              await HasPermissionAsync(OpenIddictConstants.Permissions.GrantTypes.Implicit) &&
                              (await HasPermissionAsync(OpenIddictConstants.Permissions.ResponseTypes.CodeIdToken) ||
                               await HasPermissionAsync(OpenIddictConstants.Permissions.ResponseTypes.CodeIdTokenToken) ||
                               await HasPermissionAsync(OpenIddictConstants.Permissions.ResponseTypes.CodeToken)),

            AllowImplicitFlow = await HasPermissionAsync(OpenIddictConstants.Permissions.GrantTypes.Implicit) &&
                                (await HasPermissionAsync(OpenIddictConstants.Permissions.ResponseTypes.IdToken) ||
                                 await HasPermissionAsync(OpenIddictConstants.Permissions.ResponseTypes.IdTokenToken) ||
                                 await HasPermissionAsync(OpenIddictConstants.Permissions.ResponseTypes.Token)),

            AllowPasswordFlow = await HasPermissionAsync(OpenIddictConstants.Permissions.GrantTypes.Password),
            AllowRefreshTokenFlow = await HasPermissionAsync(OpenIddictConstants.Permissions.GrantTypes.RefreshToken),
            AllowLogoutEndpoint = await HasPermissionAsync(OpenIddictConstants.Permissions.Endpoints.Logout),
            AllowIntrospectionEndpoint = await HasPermissionAsync(OpenIddictConstants.Permissions.Endpoints.Introspection),
            AllowRevocationEndpoint = await HasPermissionAsync(OpenIddictConstants.Permissions.Endpoints.Revocation),
            ClientId = (await _applicationManager.GetClientIdAsync(application))!,
            ConsentType = await _applicationManager.GetConsentTypeAsync(application),
            DisplayName = (await _applicationManager.GetDisplayNameAsync(application))!,
            Id = (await _applicationManager.GetIdAsync(application))!,
            PostLogoutRedirectUris = string.Join(" ", await _applicationManager.GetPostLogoutRedirectUrisAsync(application)),
            RedirectUris = string.Join(" ", await _applicationManager.GetRedirectUrisAsync(application)),
            Type = (await _applicationManager.GetClientTypeAsync(application))!,
            RequireProofKeyForCodeExchange = await HasRequirementAsync(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange)
        };

        await foreach (var scope in _scopeManager.ListAsync())
        {
            var scopeName = await _scopeManager.GetNameAsync(scope);
            vm.ScopeEntries.Add(new CreateViewModel.ScopeEntry
            {
                Name = scopeName!,
                Selected = await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.Prefixes.Scope + scopeName)
            });
        }

        ViewData["ReturnUrl"] = returnUrl;
        return View(vm);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(EditViewModel vm, string? returnUrl = null)
    {
        var application = await _applicationManager.FindByIdAsync(vm.Id);
        if (application == null)
        {
            return NotFound();
        }

        if (!string.IsNullOrEmpty(vm.ClientSecret) &&
            string.Equals(vm.Type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError(nameof(vm.ClientSecret), "不能为 Public Client 应用程序设置客户端密钥。");
        }
        else if (string.IsNullOrEmpty(vm.ClientSecret) &&
                 string.Equals(vm.Type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError(nameof(vm.ClientSecret), "Confidential Client 应用程序需要客户端密钥。");
        }

        if (ModelState.IsValid)
        {
            var other = await _applicationManager.FindByClientIdAsync(vm.ClientId);
            if (other != null && !string.Equals(
                    await _applicationManager.GetIdAsync(other),
                    await _applicationManager.GetIdAsync(application), StringComparison.Ordinal))
            {
                ModelState.AddModelError(nameof(vm.ClientId), "客户端Id已被另一个应用程序占用。");
            }
        }

        if (!ModelState.IsValid)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(vm);
        }

        var settings = new OpenIdApplicationSettings()
        {
            AllowAuthorizationCodeFlow = vm.AllowAuthorizationCodeFlow,
            AllowClientCredentialsFlow = vm.AllowClientCredentialsFlow,
            AllowHybridFlow = vm.AllowHybridFlow,
            AllowImplicitFlow = vm.AllowImplicitFlow,
            AllowIntrospectionEndpoint = vm.AllowIntrospectionEndpoint,
            AllowLogoutEndpoint = vm.AllowLogoutEndpoint,
            AllowPasswordFlow = vm.AllowPasswordFlow,
            AllowRefreshTokenFlow = vm.AllowRefreshTokenFlow,
            AllowRevocationEndpoint = vm.AllowRevocationEndpoint,
            ClientId = vm.ClientId,
            ClientSecret = vm.ClientSecret,
            ConsentType = vm.ConsentType,
            DisplayName = vm.DisplayName,
            PostLogoutRedirectUris = vm.PostLogoutRedirectUris,
            RedirectUris = vm.RedirectUris,
            Roles = vm.RoleEntries.Where(x => x.Selected).Select(x => x.Name).ToArray(),
            Scopes = vm.ScopeEntries.Where(x => x.Selected).Select(x => x.Name).ToArray(),
            Type = vm.Type,
            RequireProofKeyForCodeExchange = vm.RequireProofKeyForCodeExchange
        };

        await _applicationManager.UpdateDescriptorFromSettings(settings, application);

        if (string.IsNullOrEmpty(returnUrl))
        {
            return RedirectToAction(nameof(Index));
        }

        return this.LocalRedirect(returnUrl, true);
    }
    
    [HttpPost]
    public async Task<IActionResult> Delete(string id)
    {
        var application = await _applicationManager.FindByIdAsync(id);
        if (application == null)
        {
            return NotFound();
        }

        await _applicationManager.DeleteAsync(application);

        return RedirectToAction(nameof(Index));
    }

}