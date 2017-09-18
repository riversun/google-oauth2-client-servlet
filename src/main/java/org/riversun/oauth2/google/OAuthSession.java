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

import javax.servlet.http.HttpServletRequest;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;

/**
 * Get OAuth 2 status and authentication result stored in http session<br>
 * Thread-safe
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 */
public class OAuthSession {

    private static final OAuthSession instance = new OAuthSession();

    private OAuthSession() {
    }

    public static OAuthSession getInstance() {
        return instance;
    }

    /**
     * Clear OAuth2 state.Once cleared, execute OAuth flow again
     * 
     * @param req
     */
    public void clearOAuth2State(HttpServletRequest req) {
        req.getSession().setAttribute(OAuthConst.SESSION_KEY_OAUTH2_DONE, null);
    }

    /**
     * Set URL to redirect after OAuth2 flow <br>
     * This url will be cleared after OAuth2 callback received.
     * 
     * @param req
     * @param url
     */
    public void setRedirectUrlAfterOAuth(HttpServletRequest req, String url) {
        // URL to be redirected after OAuth2 flow is finished
        req.getSession().setAttribute(OAuthConst.SESSION_KEY_REDIRECT_URL_AFTER_OAUTH, url);
    }

    /**
     * Returns credential <br>
     * <br>
     * <br>
     * Why "Deprecated"<br>
     * This method store the "GoogleCredential" object to the session and reuses it, <br>
     * but since the credential object is not "serializable",<br>
     * considering of persistence of httpSession in the future<br>
     * you should not store "not-serializable" object in the session. <br>
     * <br>
     * <br>
     * Recommendation<br>
     * You should create "GoogleCredential" from access_token and refresh_token in the app lifecycle.<br>
     * {@link OAuthSession#createCredential(HttpServletRequest)}
     * 
     * @param req
     * @return
     * @throws IOException
     */
    @Deprecated
    public GoogleCredential getCredential(HttpServletRequest req) throws IOException {
        GoogleCredential credential = (GoogleCredential) req.getSession().getAttribute(OAuthConst.SESSION_KEY_CREDENTIAL);

        if (credential == null) {

            final String accessToken = getAccessToken(req);
            final String refreshToken = getRefreshToken(req);

            // create credential
            credential = OAuthUtil.createCredential(accessToken, refreshToken);
            req.getSession().setAttribute(OAuthConst.SESSION_KEY_CREDENTIAL, credential);
        }

        return credential;
    }

    /**
     * Create credential from accessToken/refreeshToken store in the session
     * 
     * @param req
     * @return
     * @throws IOException
     */
    public GoogleCredential createCredential(HttpServletRequest req) throws IOException {
        final GoogleCredential credential = OAuthUtil.createCredential(
                getAccessToken(req),
                getRefreshToken(req));
        return credential;

    }

    /**
     * Returns refresh_token stored in the session
     * 
     * @param req
     * @return
     */
    public String getRefreshToken(HttpServletRequest req) {
        return (String) req.getSession().getAttribute(OAuthConst.SESSION_KEY_REFRESH_TOKEN);
    }

    /**
     * Returns access_token stored in the session
     * 
     * @param req
     * @return
     */
    public String getAccessToken(HttpServletRequest req) {
        return (String) req.getSession().getAttribute(OAuthConst.SESSION_KEY_ACCESS_TOKEN);
    }

    /**
     * Returns unique user id (subject)
     * 
     * @param req
     * @return
     */
    public String getUserId(HttpServletRequest req) {
        final String userId = (String) req.getSession().getAttribute(OAuthConst.SESSION_KEY_UNIQUE_USER_ID);
        return userId;
    }

}
