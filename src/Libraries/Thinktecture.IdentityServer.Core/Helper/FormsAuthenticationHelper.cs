using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;

namespace Thinktecture.IdentityServer.Helper
{
    /// <summary>
    /// Provides extended functionality for ASP.NET Forms Authentication.
    /// </summary>
    public static class FormsAuthenticationHelper
    {
        static FormsAuthenticationHelper()
        {
            const string DefaultReturnUrlQueryKey = "ReturnUrl";
            const string ReturnUrlOverrideAppSettingKey = "aspnet:FormsAuthReturnUrlVar";

            ReturnUrlQueryKey = ConfigurationManager.AppSettings[ReturnUrlOverrideAppSettingKey];

            if (string.IsNullOrWhiteSpace(ReturnUrlQueryKey))
            {
                ReturnUrlQueryKey = DefaultReturnUrlQueryKey;
            }
        }

        private static string ReturnUrlQueryKey { get; set; }

        /// <summary>
        /// Redirects to the configured login page with the specified return URL.
        /// </summary>
        /// <param name="returnUrl">The return URL.</param>
        public static void RedirectToLoginPage(string returnUrl)
        {
            if (returnUrl == null)
            {
                throw new ArgumentNullException("returnUrl");
            }

            if (string.IsNullOrWhiteSpace(returnUrl))
            {
                throw new ArgumentException("The return URL cannot be an empty or whitespace only string.", "returnUrl");
            }

            HttpContext httpContext = HttpContext.Current;

            string loginUrl = FormsAuthentication.LoginUrl;

            if (loginUrl.IndexOf('?') < 0)
            {
                loginUrl += "?";
            }
            else
            {
                loginUrl += "&";
            }

            string encodedReturnUrl = HttpUtility.UrlEncode(returnUrl, httpContext.Request.ContentEncoding);

            loginUrl = string.Concat(loginUrl, ReturnUrlQueryKey, "=", encodedReturnUrl);

            httpContext.Response.Redirect(loginUrl);
        }
    }
}
