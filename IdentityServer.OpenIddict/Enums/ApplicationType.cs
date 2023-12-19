using System.ComponentModel;

namespace IdentityServer.OpenIddict.Enums;

public enum ApplicationType
{
    [Description("Confidential client")]
    ConfidentialClient = 1,
    [Description("Public client")]
    PublicClient = 2,
}