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
    public IActionResult Create()
    {
        var vm = new CreateViewModel();

        return View("Create", vm);
    }


    [HttpPost]
    public IActionResult Create(CreateViewModel vm)
    {
        return View("Create", vm);
    }
}