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
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpResponseException;

/**
 * Handling class of OAuth2/OpenId connect flow
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 * 
 */
public final class OAuthHandler {

    private static final Logger LOGGER = Logger.getLogger(OAuthHandler.class.getName());

    private final String mRedirectUrl;
    private boolean mForceUseHttps = false;

    public OAuthHandler(String redirectUrl) {
        mRedirectUrl = redirectUrl;
    }

    /**
     * Set force use HTTPS for request
     * 
     * @param enabled
     *            true:forcibly change the currently requested URL to "https"
     * @return
     */
    public OAuthHandler setForceUseHttps(boolean enabled) {
        mForceUseHttps = enabled;
        return OAuthHandler.this;
    }

    /**
     * Start OAuth2 flow<br>
     * <br>
     * 1.Get authorization code url<br>
     * <br>
     * 2.Automatically redirecting to authorization code url(like
     * https://accounts.google.com/o/oauth2/auth) for authorization code<br>
     * <br>
     * (If you have not logged in to Google yet,automatically redirecting to
     * authentication page of google account.) <br>
     * 3.(On {@link OAuthCallbackServlet}) After redirection, callback servlet
     * will receive authorization code<br>
     * <br>
     * 4.(On {@link OAuthCallbackServlet}) Request token url(like
     * https://accounts.google.com/o/oauth2/token) for tokenResponse with
     * authorization code.<br>
     * <br>
     * You can get refresh_token from tokenResponse if you request authorization
     * code for the first time with access_type="offline" . <br>
     * <br>
     * 5.(On {@link OAuthCallbackServlet}) Verify tokenResponse by
     * {@link OAuthHandler#getIdTokenAndVerify}<br>
     * <br>
     * 6.(On {@link OAuthCallbackServlet}) Remember credential(store it in http
     * session).
     * 
     * @param request
     * @param response
     * @param forceApprovalPrompt
     *            if true,force show approval prompt.<br>
     *            The authentication page(ex. A page requesting to input userId
     *            and password) will be shown.<br>
     *            After that you can get a new refresh token
     * @throws IOException
     * @throws ServletException
     */
    public void doOAuth2Flow(ServletRequest request, ServletResponse response, boolean forceApprovalPrompt) throws IOException, ServletException {

        LOGGER.fine("");

        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse resp = (HttpServletResponse) response;

        // generate state token for adressing CSRF
        final String stateToken = generateStateToken();

        LOGGER.fine("SET SESSION stateToken=" + stateToken);
        req.getSession().setAttribute(OAuthConst.SESSION_KEY_OAUTH2_STATE_TOKEN, stateToken);

        final String storedRedirectAppUrl = (String) req.getSession().getAttribute(OAuthConst.SESSION_KEY_REDIRECT_URL_AFTER_OAUTH);

        if (storedRedirectAppUrl == null) {
            
            final String currentUrl = getCurrentUrl(req, mForceUseHttps);

            LOGGER.fine("SET SESSION currentUrl=" + currentUrl);
            req.getSession().setAttribute(OAuthConst.SESSION_KEY_REDIRECT_URL_AFTER_OAUTH, currentUrl);

        } else {

        }
        
        final GoogleAuthorizationCodeRequestUrl authorizationCodeRequestUrl = OAuthCommon.createFlow()
                .newAuthorizationUrl()
                .setAccessType("offline")
                .setRedirectUri(mRedirectUrl)
                .setState(stateToken);

        if (forceApprovalPrompt) {
            // When you want to confirm every time (set both
            // setAccessType ("offline") and setApprovalPrompt("force"), you can
            // get refreshtoken every time.
            authorizationCodeRequestUrl.setApprovalPrompt("force");
        }

        final String authUrl = authorizationCodeRequestUrl.toString();

        LOGGER.fine("redirect to auth url=" + authorizationCodeRequestUrl.toString());

        // redirect to authorization code request url
        resp.sendRedirect(authUrl);

    }

    /**
     * generate state
     * 
     * @return
     */
    private final String generateStateToken() {
        final String stateToken = new BigInteger(130, new SecureRandom()).toString(32);
        return stateToken;
    }

    /**
     * Returns the currently requested URL
     * 
     * @param req
     * @param forceUseHttps
     *            true:forcibly change the currently requested URL to "https"
     * @return
     */
    private String getCurrentUrl(final HttpServletRequest req, boolean forceUseHttps) {

        final String scheme = forceUseHttps ? "https" : req.getScheme();
        final int currentPort = req.getServerPort();

        final StringBuilder sb = new StringBuilder();

        sb.append(scheme);
        sb.append("://");
        sb.append(req.getServerName());

        if (currentPort != 80 && currentPort != 443) {
            sb.append(":");
            sb.append(currentPort);
        }

        sb.append(req.getRequestURI());

        if (req.getQueryString() != null && !req.getQueryString().isEmpty()) {
            sb.append("?");
            sb.append(req.getQueryString());
        }

        final String currentUrl = sb.toString();

        return currentUrl;
    }

    /**
     * Get token response by authorization code<br>
     * 
     * @param code
     * @return
     */
    public GoogleTokenResponse getTokenResponseFromCode(String code) {

        LOGGER.fine("code=" + code);

        GoogleTokenResponse tokenResponse = null;

        try {

            final GoogleAuthorizationCodeFlow flow = OAuthCommon.createFlow();

            LOGGER.fine("execute newTokenRequest(" + code + ")");

            tokenResponse = flow
                    .newTokenRequest(code)
                    .setRedirectUri(mRedirectUrl)
                    .execute();

        } catch (Exception e) {

            e.printStackTrace();
            LOGGER.warning("Please check whether you are reloading on the OAuth callback servlet");
            // {
            // "error" : "invalid_grant",
            // "error_description" : "Code was already redeemed."
            // }

            // TODO
            e.printStackTrace();

        }

        return tokenResponse;
    }

    /**
     * Parse tokenResponse and returns idToken
     * 
     * @param tokenResponse
     * @return
     */
    public GoogleIdToken getIdToken(GoogleTokenResponse tokenResponse) {

        LOGGER.fine("");

        if (tokenResponse == null) {
            return null;
        }

        // GoogleIdTokenVerifier is Not-thread-safe.
        // access "https://www.googleapis.com/oauth2/v1/certs" for verification
        final GoogleIdTokenVerifier idTokenVerifier = new GoogleIdTokenVerifier(OAuthCommon.HTTP_TRANSPORT, OAuthCommon.JSON_FACTORY);

        GoogleIdToken idToken = null;

        try {
            idToken = GoogleIdToken.parse(OAuthCommon.JSON_FACTORY, tokenResponse.getIdToken());

            if (!idTokenVerifier.verify(idToken)) {
                return null;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return idToken;
    }

    /**
     * Returns true if token revocation occurred
     * 
     * @param e
     * @return
     */
    public boolean isRevocationRelatedException(Exception e) {

        // TODO:
        if (e instanceof TokenResponseException) {

            if (((TokenResponseException) e).getContent().contains("invalid_grant")) {
                return true;
            }

        } else if (e instanceof HttpResponseException) {

            if (((HttpResponseException) e).getContent().contains("Invalid Credentials")) {
                return true;
            }

        }

        return false;
    }
}
