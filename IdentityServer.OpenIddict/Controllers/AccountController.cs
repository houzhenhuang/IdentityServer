using IdentityServer.OpenIddict.Data;
using IdentityServer.OpenIddict.Models;
using IdentityServer.OpenIddict.ViewModels.Account;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.OpenIddict.Controllers;

[Authorize]
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ApplicationDbContext _applicationDbContext;
    private static bool _databaseChecked;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext applicationDbContext, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _applicationDbContext = applicationDbContext;
        _signInManager = signInManager;
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string returnUrl = null)
    {
        if (HttpContext.User?.Identity?.IsAuthenticated ?? false)
        {
            returnUrl = null;
        }

        // Clear the existing external cookie to ensure a clean login process.
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        var schemes = await _signInManager.GetExternalAuthenticationSchemesAsync();

        CopyTempDataErrorsToModelState();

        ViewData["ReturnUrl"] = returnUrl;

        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl ??= "/";

        if (model == null)
        {
            throw new ArgumentNullException(nameof(model));
        }

        if (TryValidateModel(model) && ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                // _logger.LogInformation(LoggerEventIds.UserLogin, "User logged in.");
                return LocalRedirect(returnUrl);
            }

            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
            }

            if (result.IsLockedOut)
            {
                // _logger.LogWarning(LoggerEventIds.UserLockout, "User account locked out.");
                return RedirectToPage("./Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }
        }

        // If we got this far, something failed, redisplay form.
        return View(model);
    }


    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(string provider, string returnUrl = null)
    {
        // Request a redirect to the external login provider.
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

        return Challenge(properties, provider);
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
    {
        return RedirectToLogin(returnUrl);
    }

    //
    // POST: /Account/Register
    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
    {
        EnsureDatabaseCreated(_applicationDbContext);
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user != null)
            {
                return StatusCode(StatusCodes.Status409Conflict);
            }

            user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return Ok();
            }

            AddErrors(result);
        }

        // If we got this far, something failed.
        return BadRequest(ModelState);
    }

    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(string returnUrl = null)
    {
        await _signInManager.SignOutAsync();
        // _logger.LogInformation(4, "User logged out.");

        return RedirectToLocal(returnUrl);
    }

    #region Helpers

    // The following code creates the database and schema if they don't exist.
    // This is a temporary workaround since deploying database through EF migrations is
    // not yet supported in this release.
    // Please see this http://go.microsoft.com/fwlink/?LinkID=615859 for more information on how to do deploy the database
    // when publishing your application.
    private static void EnsureDatabaseCreated(ApplicationDbContext context)
    {
        if (!_databaseChecked)
        {
            _databaseChecked = true;
            context.Database.EnsureCreated();
        }
    }

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }

    private void CopyTempDataErrorsToModelState()
    {
        foreach (var errorMessage in TempData.Where(x => x.Key.StartsWith("error")).Select(x => x.Value.ToString()))
        {
            ModelState.AddModelError(string.Empty, errorMessage);
        }
    }

    private RedirectToActionResult RedirectToLogin(string returnUrl)
    {
        CopyModelStateErrorsToTempData();

        return RedirectToAction(nameof(Login), new { returnUrl });
    }

    private void CopyModelStateErrorsToTempData(string key = "")
    {
        var iix = 0;

        foreach (var state in ModelState)
        {
            if (key != null && state.Key != key)
            {
                continue;
            }

            foreach (var item in state.Value.Errors)
            {
                TempData[$"error_{iix++}"] = item.ErrorMessage;
            }
        }
    }

    protected IActionResult RedirectToLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return Redirect("~/");
    }
    
    #endregion
}