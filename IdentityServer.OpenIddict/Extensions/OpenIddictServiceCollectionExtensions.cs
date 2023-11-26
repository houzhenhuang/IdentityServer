using IdentityServer.OpenIddict;
using IdentityServer.OpenIddict.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Microsoft.Extensions.DependencyInjection;

public static class OpenIddictServiceCollectionExtensions
{
    public static IServiceCollection AddOpenIddictService(this IServiceCollection services)
    {
        services.AddOpenIddict()
            // 注册 OpenIddict 核心组件。
            .AddCore(options =>
            {
                // 配置 OpenIddict 以使用 Entity Framework Core 存储和模型。
                // 注意：调用 ReplaceDefaultEntities() 来替换默认实体。
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })
            // 注册 OpenIddict 服务器组件。
            .AddServer(options =>
            {
                // Enable the token endpoint.
                options.SetAuthorizationEndpointUris("connect/authorize")
                    .SetLogoutEndpointUris("connect/logout")
                    .SetTokenEndpointUris("connect/token")
                    .SetUserinfoEndpointUris("connect/userinfo");

                // Mark the "email", "profile" and "roles" scopes as supported scopes.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);
                
                // Enable the client credentials flow.
                options.AllowClientCredentialsFlow();

                // Enable the password flow.
                options.AllowPasswordFlow()
                    .AllowRefreshTokenFlow();
                
                // Note: this sample only uses the authorization code flow but you can enable
                // the other flows if you need to support implicit, password or client credentials.
                options.AllowAuthorizationCodeFlow();

                // Accept anonymous clients (i.e clients that don't send a client_id).
                options.AcceptAnonymousClients();

                // 注册签名和加密凭据。
                options.AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();

                // 注册 ASP.NET Core 主机并配置 ASP.NET Core 选项。
                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableLogoutEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserinfoEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();

                // options.DisableAccessTokenEncryption();
            })
            // 注册 OpenIddict 验证组件。
            .AddValidation(options =>
            {
                // 从本地 OpenIddict 服务器实例导入配置。
                options.UseLocalServer();

                // 注册 ASP.NET Core 主机。
                options.UseAspNetCore();
            });

        services.AddHostedService<Worker>();

        return services;
    }
}