using IdentityServer.OpenIddict.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.OpenIddict.Controllers;

[Route("api")]
public class ResourceController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public ResourceController(IOpenIddictApplicationManager applicationManager, UserManager<ApplicationUser> userManager)
    {
        _applicationManager = applicationManager;
        _userManager = userManager;
    }

    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("message")]
    public async Task<IActionResult> GetMessage()
    {
        var subject = User.FindFirst(Claims.Subject)?.Value;
        if (string.IsNullOrEmpty(subject))
        {
            return BadRequest();
        }

        var application = await _applicationManager.FindByClientIdAsync(subject);
        if (application == null)
        {
            return BadRequest();
        }

        return Content($"{await _applicationManager.GetDisplayNameAsync(application)} 已成功通过身份验证。");
    }
    
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("message-with-password-grant-type")]
    public async Task<IActionResult> GetMessageWithPasswordGrantType()
    {
        var user = await _userManager.FindByIdAsync(User.GetClaim(Claims.Subject));
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictValidationAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictValidationAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        return Content($"{user.UserName} 已成功通过身份验证。");
    }
}