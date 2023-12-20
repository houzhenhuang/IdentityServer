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

    public ApplicationController(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var vm = new IndexViewModel();

        await foreach (var application in _applicationManager.ListAsync(20, 0))
        {
            vm.Applications.Add(new OpenIdApplicationEntry
            {
                DisplayName = await _applicationManager.GetDisplayNameAsync(application),
                Id = await _applicationManager.GetIdAsync(application)
            });
        }

        return View("Index", vm);
    }

    [HttpGet]
    public IActionResult Create(string returnUrl = null)
    {
        var vm = new CreateViewModel();

        ViewData["ReturnUrl"] = returnUrl;
        return View(vm);
    }


    [HttpPost]
    public async Task<IActionResult> Create(CreateViewModel vm,string returnUrl = null)
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
        
        var settings = new  OpenIdApplicationSettings()
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
}