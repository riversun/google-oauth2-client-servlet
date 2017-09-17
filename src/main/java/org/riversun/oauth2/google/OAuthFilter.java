/*
 * 
 * Copyright 2016-2017 Tom Misawa, riversun.org@gmail.com
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the "Software"), to deal in the 
 * Software without restriction, including without limitation the rights to use, 
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
 * Software, and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 *  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */
package org.riversun.oauth2.google;

import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.api.client.http.HttpResponseException;

/**
 * Servlet filter for OAuth2
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 *
 */
public abstract class OAuthFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(OAuthFilter.class.getName());
    private static final String OAUTH2_SCOPE_OPENID = "openid";

    @Override
    public final void init(FilterConfig config) throws ServletException {
        // - Filter#Init is called when the filter is instantiated for the first
        // time.
        LOGGER.fine("");

        // initialize scope for OAuth2
        OAuthCommon.SCOPES.clear();
        OAuthCommon.SCOPES.add(OAUTH2_SCOPE_OPENID);
        OAuthCommon.SCOPES.addAll(getScopes());
    }

    /**
     * Returns authorization redirect url
     * 
     * @return
     */
    protected abstract String getAuthRedirectUrl();

    /**
     * Returns OAuth2 scopes
     * 
     * @return
     */
    protected abstract List<String> getScopes();

    /**
     * Returns true if you want to handle token revocation automatically when
     * your servlet throws exception due to refresh_token revocation.<br>
     * <br>
     * Automatic handling of refresh token revocation is to redisplay user's
     * approval screen and get a new token automatically. <br>
     * <br>
     * Please be aware that processing in servlet will be invalid if the order
     * of processing your servlet logic is incorrect.
     * 
     * @return
     */
    protected boolean isAutoHandleRefreshTokenRevocation() {
        return true;
    }

    /**
     * Returns true:<br>
     * check authentication every time(every access)<br>
     * <br>
     * <br>
     * Returns false:<br>
     * For example,once the user has "authenticated" , the web application can
     * continue using "authorized" action using the access_token (or via
     * refresh_token) even though the user has signed out from Google.<br>
     * When you use your original authentication mechanism instead of using
     * openId (like Google's) for authentication, return "false" in many cases.
     * 
     * @return
     */
    protected boolean isAuthenticateEverytime() {
        return true;
    }

    protected boolean isForceHttps() {
        return false;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        LOGGER.fine("");

        final OAuthHandler oh = new OAuthHandler(getAuthRedirectUrl())
                .setForceUseHttps(isForceHttps());

        if (isOAuth2Done(request, response)) {
            // - If OAuth2 flow has already been passed

            LOGGER.fine("OAuth2 already passed");

            try {
                chain.doFilter(request, response);
            } catch (HttpResponseException e) {
                if (oh.isRevocationRelatedException(e)) {

                    LOGGER.warning("Refresh token not found or revoked.Force show authorization page.");
                    final boolean forceApprovalPrompt = true;
                    oh.doOAuth2Flow(request, response, forceApprovalPrompt);
                }
            }

        } else {
            // - If OAuth2 flow has not been passed yet
            final boolean forceApprovalPrompt = false;

            // do oauth2 flow
            oh.doOAuth2Flow(request, response, forceApprovalPrompt);
        }

    }

    /**
     * Check if OAuth2 flow has already been passed.
     * 
     * @param request
     * @param response
     * @return
     * @throws IOException
     * @throws ServletException
     */
    private boolean isOAuth2Done(ServletRequest request, ServletResponse response) throws IOException, ServletException {

        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse resp = (HttpServletResponse) response;

        // sessionにACCESS_TOKENが存在するかチェックする
        final HttpSession session = req.getSession();

        final boolean isOAuth2Done = session.getAttribute(OAuthConst.SESSION_KEY_OAUTH2_DONE) != null;

        LOGGER.fine("isOAuth2Done=" + isOAuth2Done);

        if (isOAuth2Done) {

            // - If already authenticated

            if (isAuthenticateEverytime()) {
                session.setAttribute(OAuthConst.SESSION_KEY_OAUTH2_DONE, null);
            }

            return true;

        } else {

            return false;

        }
    }

    @Override
    public void destroy() {
    }

}