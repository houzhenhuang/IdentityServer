using System.Collections.Immutable;
using System.Security.Claims;
using IdentityServer.OpenIddict.Models;
using IdentityServer.OpenIddict.ViewModels.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.OpenIddict.Controllers;

[Route("connect/authorize")]
public class AuthorizationController : ControllerBase
{
    public AuthorizationController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager)
        : base(signInManager, userManager, applicationManager, authorizationManager, scopeManager)
    {
    }

    [HttpGet, HttpPost]
    [IgnoreAntiforgeryToken]
    public virtual async Task<IActionResult> HandleAsync()
    {
        var request = await GetOpenIddictServerRequestAsync(HttpContext);

        // 如果客户端应用程序指定了 prompt＝login，立即将用户代理返回到登录页面。
        if (request.HasPrompt(Prompts.Login))
        {
            // 为了避免无休止的登录->授权重定向，在重定向用户之前，将从授权请求负载中删除 prompt=login 标志。
            var prompt = string.Join(" ", request.GetPrompts().Remove(Prompts.Login));

            var parameters = Request.HasFormContentType
                ? Request.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList()
                : Request.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();

            parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                });
        }

        // 检索存储在身份验证 cookie 中的用户主体。
        // 如果提供了 max_age 参数，请确保 cookie 不是太旧。
        // 如果无法提取用户主体或 cookie 太旧，请将用户重定向到登录页面。
        var result = await HttpContext.AuthenticateAsync();
        if (result is not { Succeeded: true } || (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
                                                  DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)))
        {
            // 如果客户端应用程序请求无提示身份验证，返回错误，表明用户未登录。
            if (request.HasPrompt(Prompts.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "用户尚未登录。"
                    }!));
            }

            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        //检索已登录用户的个人资料。
        var user = await UserManager.GetUserAsync(result.Principal);
        if (user == null)
        {
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        // 从数据库中检索应用程序详细信息。
        var application = await ApplicationManager.FindByClientIdAsync(request.ClientId!) ??
                          throw new InvalidOperationException("无法找到有关调用客户端应用程序的详细信息。");

        // 检索与用户和调用客户端应用程序关联的永久授权。
        var authorizations = await AuthorizationManager.FindAsync(
            subject: await UserManager.GetUserIdAsync(user),
            client: (await ApplicationManager.GetIdAsync(application))!,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        switch (await ApplicationManager.GetConsentTypeAsync(application))
        {
            // 如果同意是外部的（例如，当系统管理员授予授权时），
            // 如果在数据库中找不到授权，则立即返回错误。
            case ConsentTypes.External when !authorizations.Any():
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "不允许登录的用户访问此客户端应用程序。"
                    }!));

            // 如果默示同意或找到授权，返回授权响应而不显示同意书。
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
            case ConsentTypes.Explicit when authorizations.Any() && !request.HasPrompt(Prompts.Consent):
                // 创建 OpenIddict 将用于生成令牌的基于声明的标识。
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // 添加将保留在 tokens 中的 claims 。
                identity.SetClaim(Claims.Subject, await UserManager.GetUserIdAsync(user))
                    .SetClaim(Claims.Email, await UserManager.GetEmailAsync(user))
                    .SetClaim(Claims.Name, await UserManager.GetUserNameAsync(user))
                    .SetClaims(Claims.Role, (await UserManager.GetRolesAsync(user)).ToImmutableArray());

                // 注意：在此示例中，授予的范围与请求的范围匹配，但您可能希望允许用户取消选中特定范围。
                // 为此，只需在调用 SetScopes 之前限制范围列表即可。
                identity.SetScopes(request.GetScopes());
                identity.SetResources(await ScopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

                // 自动创建永久授权，以避免未来授权或包含相同范围的令牌请求需要明确同意。
                var authorization = authorizations.LastOrDefault();
                authorization ??= await AuthorizationManager.CreateAsync(
                    identity: identity,
                    subject: await UserManager.GetUserIdAsync(user),
                    client: (await ApplicationManager.GetIdAsync(application))!,
                    type: AuthorizationTypes.Permanent,
                    scopes: identity.GetScopes());

                identity.SetAuthorizationId(await AuthorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(GetDestinations);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // 此时，数据库中未发现任何授权，如果客户端应用程序在授权请求中指定 prompt=none，则必须返回错误。
            case ConsentTypes.Explicit when request.HasPrompt(Prompts.None):
            case ConsentTypes.Systematic when request.HasPrompt(Prompts.None):
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "需要交互式用户同意。"
                    }!));

            // 在所有其他情况下，请提交同意书。
            default:
                return View("Authorize", new AuthorizeViewModel
                {
                    ApplicationName = (await ApplicationManager.GetLocalizedDisplayNameAsync(application))!,
                    Scope = request.Scope!
                });
        }
    }


    //     [HttpPost]
    // [Authorize]
    // [Route("callback")]
    // public virtual async Task<IActionResult> HandleCallbackAsync()
    // {
    //     // 拒绝授权
    //     if (await HasFormValueAsync("deny"))
    //     {
    //         // Notify OpenIddict that the authorization grant has been denied by the resource owner
    //         // to redirect the user agent to the client application using the appropriate response_mode.
    //         return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    //     }
    //
    //     var request = await GetOpenIddictServerRequestAsync(HttpContext);
    //     // 检索已登录用户的个人资料。
    //     var user = await UserManager.GetUserAsync(User) ??
    //                throw new InvalidOperationException("无法检索用户详细信息。");
    //
    //     // 从数据库中检索应用程序详细信息。
    //     var application = await ApplicationManager.FindByClientIdAsync(request.ClientId!) ??
    //                       throw new InvalidOperationException("无法找到有关调用客户端应用程序的详细信息。");
    //
    //     // 检索与用户和调用客户端应用程序关联的永久授权
    //     var authorizations = await AuthorizationManager.FindAsync(
    //         subject: await UserManager.GetUserIdAsync(user),
    //         client: (await ApplicationManager.GetIdAsync(application))!,
    //         status: Statuses.Valid,
    //         type: AuthorizationTypes.Permanent,
    //         scopes: request.GetScopes()).ToListAsync();
    //
    //     // 注意：在其他操作中已经进行了相同的检查，但在此处重复进行，以确保恶意用户无法滥用此仅 POST 端点并强制其在未经外部授权的情况下返回有效响应。
    //     if (!authorizations.Any() && await ApplicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
    //     {
    //         return Forbid(
    //             authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
    //             properties: new AuthenticationProperties(new Dictionary<string, string>
    //             {
    //                 [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
    //                 [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "不允许登录的用户访问此客户端应用程序。"
    //             }!));
    //     }
    //
    //     // 创建 OpenIddict 将使用的基于声明的身份来生成tokens。
    //     var identity = new ClaimsIdentity(
    //         authenticationType: TokenValidationParameters.DefaultAuthenticationType,
    //         nameType: Claims.Name,
    //         roleType: Claims.Role);
    //
    //     // 添加将保留在 tokens 中的声明。
    //     identity.SetClaim(Claims.Subject, await UserManager.GetUserIdAsync(user))
    //         .SetClaim(Claims.Email, await UserManager.GetEmailAsync(user))
    //         .SetClaim(Claims.Name, await UserManager.GetUserNameAsync(user))
    //         .SetClaims(Claims.Role, (await UserManager.GetRolesAsync(user)).ToImmutableArray());
    //
    //     // 注意：在此示例中，授予的范围与请求的范围匹配，但您可能希望允许用户取消选中特定范围。为此，只需在调用 SetScopes 之前限制范围列表即可。
    //     identity.SetScopes(request.GetScopes());
    //     identity.SetResources(await ScopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
    //
    //     // 自动创建永久授权，以避免未来授权或包含相同范围的令牌请求需要明确同意。
    //     var authorization = authorizations.LastOrDefault();
    //     authorization ??= await AuthorizationManager.CreateAsync(
    //         identity: identity,
    //         subject: await UserManager.GetUserIdAsync(user),
    //         client: (await ApplicationManager.GetIdAsync(application))!,
    //         type: AuthorizationTypes.Permanent,
    //         scopes: identity.GetScopes());
    //
    //     identity.SetAuthorizationId(await AuthorizationManager.GetIdAsync(authorization));
    //     identity.SetDestinations(GetDestinations);
    //
    //     // 返回 SignInResult 将要求 OpenIddict 颁发适当的 access/identity tokens。
    //     return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    // }

    [Authorize, FormValueRequired("submit.Accept")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Accept()
    {
        var request = await GetOpenIddictServerRequestAsync(HttpContext);

        // 检索已登录用户的配置文件。
        var user = await UserManager.GetUserAsync(User) ??
                   throw new InvalidOperationException("The user details cannot be retrieved.");

        // 从数据库中检索应用程序详细信息。
        var application = await ApplicationManager.FindByClientIdAsync(request.ClientId!) ??
                          throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // 检索与用户和调用客户端应用程序相关联的永久授权。
        var authorizations = await AuthorizationManager.FindAsync(
            subject: await UserManager.GetUserIdAsync(user),
            client: (await ApplicationManager.GetIdAsync(application))!,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        // 注意：在其他操作中已经进行了相同的检查，但在此处重复进行，以确保恶意用户不会滥用此仅限POST的端点，并在没有外部授权的情况下强制其返回有效响应。
        if (!authorizations.Any() && await ApplicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                }!));
        }

        // 创建OpenIddict将用于生成令牌的基于声明的标识。
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // 添加将在令牌中持久化的声明。
        identity.SetClaim(Claims.Subject, await UserManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email, await UserManager.GetEmailAsync(user))
            .SetClaim(Claims.Name, await UserManager.GetUserNameAsync(user))
            .SetClaims(Claims.Role, (await UserManager.GetRolesAsync(user)).ToImmutableArray());

        // 注意：在此示例中，授予的作用域与请求的作用域匹配，但您可能希望允许用户取消选中特定的作用域。为此，只需在调用SetScope之前限制作用域列表即可。
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await ScopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

        // 自动创建永久授权，以避免将来的授权或包含相同作用域的令牌请求需要明确同意。
        var authorization = authorizations.LastOrDefault();
        authorization ??= await AuthorizationManager.CreateAsync(
            identity: identity,
            subject: await UserManager.GetUserIdAsync(user),
            client: (await ApplicationManager.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());

        identity.SetAuthorizationId(await AuthorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

        // 返回 SignInResult 将要求OpenIddict发布适当的访问/身份令牌。
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    // 通知OpenIddict资源所有者拒绝授权授予，以便使用适当的response_mode将用户代理重定向到客户端应用程序。
    public IActionResult Deny() => Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}

public sealed class FormValueRequiredAttribute : ActionMethodSelectorAttribute
{
    private readonly string _name;

    public FormValueRequiredAttribute(string name)
    {
        _name = name;
    }

    public override bool IsValidForRequest(RouteContext context, ActionDescriptor action)
    {
        if (string.Equals(context.HttpContext.Request.Method, "GET", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.HttpContext.Request.Method, "HEAD", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.HttpContext.Request.Method, "DELETE", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.HttpContext.Request.Method, "TRACE", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrEmpty(context.HttpContext.Request.ContentType))
        {
            return false;
        }

        if (!context.HttpContext.Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !string.IsNullOrEmpty(context.HttpContext.Request.Form[_name]);
    }
}