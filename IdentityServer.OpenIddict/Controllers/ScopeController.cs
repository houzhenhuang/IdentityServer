using IdentityServer.OpenIddict.Models;
using IdentityServer.OpenIddict.ViewModels.Scope;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using IdentityServer.OpenIddict.Extensions;

namespace IdentityServer.OpenIddict.Controllers;

[Authorize(AuthenticationSchemes = "Identity.Application")]
public class ScopeController : Controller
{
    private readonly IOpenIddictScopeManager _scopeManager;

    public ScopeController(IOpenIddictScopeManager scopeManager)
    {
        _scopeManager = scopeManager;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var vm = new IndexViewModel();

        await foreach (var scope in _scopeManager.ListAsync(20, 0))
        {
            vm.Scopes.Add(new OpenIdScopeEntry
            {
                Description = (await _scopeManager.GetDescriptionAsync(scope))!,
                DisplayName = (await _scopeManager.GetDisplayNameAsync(scope))!,
                Id = (await _scopeManager.GetIdAsync(scope))!,
                Name = (await _scopeManager.GetNameAsync(scope))!
            });
        }

        return View(nameof(Index), vm);
    }

    [HttpGet]
    public IActionResult Create(string? returnUrl = null)
    {
        var vm = new CreateViewModel();

        ViewData["ReturnUrl"] = returnUrl;

        return View(vm);
    }

    [HttpPost]
    public async Task<IActionResult> Create(CreateViewModel vm, string? returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(vm);
        }

        if (await _scopeManager.FindByNameAsync(vm.Name) != null)
        {
            ModelState.AddModelError(nameof(vm.Name), "该名称已被另一个范围占用。");
        }

        if (!ModelState.IsValid)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(vm);
        }

        var descriptor = new OpenIdScopeDescriptor
        {
            Description = vm.Description,
            DisplayName = vm.DisplayName,
            Name = vm.Name
        };

        if (!string.IsNullOrEmpty(vm.Resources))
        {
            descriptor.Resources.UnionWith(vm.Resources.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        }

        await _scopeManager.CreateAsync(descriptor);

        if (string.IsNullOrEmpty(returnUrl))
        {
            return RedirectToAction("Index");
        }

        return this.LocalRedirect(returnUrl, true);
    }

    [HttpGet]
    public async Task<IActionResult> Edit(string id, string? returnUrl = null)
    {
        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null)
        {
            return NotFound();
        }

        var model = new EditViewModel
        {
            Description = await _scopeManager.GetDescriptionAsync(scope),
            DisplayName = (await _scopeManager.GetDisplayNameAsync(scope))!,
            Id = (await _scopeManager.GetIdAsync(scope))!,
            Name = (await _scopeManager.GetNameAsync(scope))!
        };

        var resources = await _scopeManager.GetResourcesAsync(scope);

        model.Resources = string.Join(" ", resources);

        ViewData["ReturnUrl"] = returnUrl;
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(EditViewModel vm, string? returnUrl = null)
    {
        var scope = await _scopeManager.FindByIdAsync(vm.Id);
        if (scope == null)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            var other = await _scopeManager.FindByNameAsync(vm.Name);
            if (other != null && !string.Equals(
                    await _scopeManager.GetIdAsync(other),
                    await _scopeManager.GetIdAsync(scope)))
            {
                ModelState.AddModelError(nameof(vm.Name), "该名称已被另一个范围占用。");
            }
        }

        if (!ModelState.IsValid)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(vm);
        }

        var descriptor = new OpenIdScopeDescriptor();
        await _scopeManager.PopulateAsync(descriptor, scope);

        descriptor.Description = vm.Description;
        descriptor.DisplayName = vm.DisplayName;
        descriptor.Name = vm.Name;

        descriptor.Resources.Clear();

        if (!string.IsNullOrEmpty(vm.Resources))
        {
            descriptor.Resources.UnionWith(vm.Resources.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        }

        await _scopeManager.UpdateAsync(scope, descriptor);

        if (string.IsNullOrEmpty(returnUrl))
        {
            return RedirectToAction("Index");
        }

        return this.LocalRedirect(returnUrl, true);
    }

    [HttpPost]
    public async Task<IActionResult> Delete(string id)
    {
        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null)
        {
            return NotFound();
        }

        await _scopeManager.DeleteAsync(scope);

        return RedirectToAction(nameof(Index));
    }
}