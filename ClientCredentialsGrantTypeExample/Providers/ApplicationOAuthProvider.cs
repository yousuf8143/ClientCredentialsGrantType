using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace ClientCredentialsGrantTypeExample.Providers
{
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;

            if ((!context.TryGetFormCredentials(out clientId, out clientSecret)) &&
                (!context.TryGetBasicCredentials(out clientId, out clientSecret)))
                return base.ValidateClientAuthentication(context);

            if (clientId == "1" && clientSecret == "democlient")
            {
                context.Validated(clientId);
            }
            return base.ValidateClientAuthentication(context);
        }
        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, "Widgets"));
            var ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());
            context.Validated(ticket);
            return base.GrantClientCredentials(context);
        }
    }
}