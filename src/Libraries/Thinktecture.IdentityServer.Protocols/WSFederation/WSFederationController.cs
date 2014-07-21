/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.Composition;
using System.Globalization;
using System.IdentityModel.Services;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Web.UI;
using Thinktecture.IdentityModel.Authorization;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Helper;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Protocols.WSFederation
{
    public class WSFederationController : Controller
    {
        const string _cookieName = "wsfedsignout";

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public WSFederationController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public WSFederationController(IConfigurationRepository configurationRepository)
        {
            ConfigurationRepository = configurationRepository;
        }

        [OutputCache(Location = OutputCacheLocation.None, NoStore=true)]
        public ActionResult Issue()
        {
            bool isUserAuthorized = ClaimsAuthorization.CheckAccess(Constants.Actions.Issue, Constants.Resources.WSFederation);

            if (!isUserAuthorized)
            {
                string issueUrlWithoutFreshness = GetIssueUrlWithoutFreshness();

                FormsAuthenticationHelper.RedirectToLoginPage(returnUrl: issueUrlWithoutFreshness);
            }

            Tracing.Start("WS-Federation endpoint.");

            if (!ConfigurationRepository.WSFederation.Enabled && ConfigurationRepository.WSFederation.EnableAuthentication)
            {
                return new HttpNotFoundResult();
            }

            var message = WSFederationMessage.CreateFromUri(HttpContext.Request.Url);

            // sign in 
            var signinMessage = message as SignInRequestMessage;
            if (signinMessage != null)
            {
                return ProcessWSFederationSignIn(signinMessage, ClaimsPrincipal.Current);
            }

            // sign out
            var signoutMessage = message as SignOutRequestMessage;
            if (signoutMessage != null)
            {
                return ProcessWSFederationSignOut(signoutMessage);
            }

            return View("Error");
        }

        #region Helper
        private ActionResult ProcessWSFederationSignIn(SignInRequestMessage message, ClaimsPrincipal principal)
        {
            // ensure required credentials freshness
            int requiredFreshnessInMinutes;
            if (int.TryParse(message.Freshness, NumberStyles.Integer, CultureInfo.InvariantCulture, out requiredFreshnessInMinutes) && requiredFreshnessInMinutes >= 0)
            {
                var authenticationInstantClaim = principal.FindFirst(ClaimTypes.AuthenticationInstant);

                if (authenticationInstantClaim == null)
                {
                    throw new InvalidOperationException("Could not find the authentication instant claim.");
                }

                DateTime authenticationInstantUtc;
                if (!DateTime.TryParseExact(authenticationInstantClaim.Value, DateTimeFormats.Accepted, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out authenticationInstantUtc))
                {
                    throw new InvalidOperationException("The authentication instant claim contains an unsupported value.");
                }

                if (authenticationInstantUtc < DateTime.UtcNow.AddMinutes(-requiredFreshnessInMinutes))
                {
                    string issueUrlWithoutFreshness = GetIssueUrlWithoutFreshness();

                    FormsAuthenticationHelper.RedirectToLoginPage(returnUrl: issueUrlWithoutFreshness);
                }
            };

            // issue token and create ws-fed response
            var response = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                message,
                principal as ClaimsPrincipal,
                TokenServiceConfiguration.Current.CreateSecurityTokenService());

            // set cookie for single-sign-out
            new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime)
                .AddEndpoint(response.BaseUri.AbsoluteUri);

            return new WSFederationResult(response, requireSsl: ConfigurationRepository.WSFederation.RequireSslForReplyTo);
        }

        private string GetIssueUrlWithoutFreshness()
        {
            const string WSFederationFreshnessQueryStringKeyName = "wfresh";

            var queryStringCollection = HttpUtility.ParseQueryString(this.Request.Url.Query);

            queryStringCollection.Remove(WSFederationFreshnessQueryStringKeyName);

            string issueUrlWithoutFreshness = this.Request.Url.AbsolutePath + "?" + queryStringCollection.ToString();
            return issueUrlWithoutFreshness;
        }

        private ActionResult ProcessWSFederationSignOut(SignOutRequestMessage message)
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();

            var mgr = new SignInSessionsManager(HttpContext, _cookieName);

            // check for return url
            if (!string.IsNullOrWhiteSpace(message.Reply) && mgr.ContainsUrl(message.Reply))
            {
                ViewBag.ReturnUrl = message.Reply;
            }

            // check for existing sign in sessions
            var realms = mgr.GetEndpoints();
            mgr.ClearEndpoints();
            
            return View("Signout", realms);
        }
        #endregion
    }
}
