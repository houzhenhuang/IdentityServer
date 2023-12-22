using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using IdentityServer.OpenIddict.Models;
using IdentityServer.OpenIddict.ViewModels;
using Microsoft.AspNetCore.Authorization;

namespace IdentityServer.OpenIddict.Controllers;

[Authorize(AuthenticationSchemes = "Identity.Application")]
public class HomeController : Controller
{
    private const string HomeDirectory = "~/Views/Home";
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View("_ContentLayout", new ContentLayoutViewModel { HeaderView = $"{HomeDirectory}/Index/Header.cshtml", ContentView = $"{HomeDirectory}/Index/Content.cshtml" });
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}