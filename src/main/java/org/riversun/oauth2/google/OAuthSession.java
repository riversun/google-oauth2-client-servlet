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

import javax.servlet.http.HttpServletRequest;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;

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
     * set URL to redirect after OAuth2 flow
     * 
     * @param req
     * @param url
     */
    public void setRedirectUrlAfterOAuth(HttpServletRequest req, String url) {
        // URL to be redirected after OAuth2 flow is finished
        req.getSession().setAttribute(OAuthConst.SESSION_KEY_REDIRECT_URL_AFTER_OAUTH, url);
    }

    /**
     * Returns credential
     * 
     * @param req
     * @return
     */
    public GoogleCredential getCredential(HttpServletRequest req) {
        final GoogleCredential credential = (GoogleCredential) req.getSession().getAttribute(OAuthConst.SESSION_KEY_CREDENTIAL);
        return credential;
    }

    /**
     * Returns idToken
     * 
     * @param req
     * @return
     */
    public GoogleIdToken getIdToken(HttpServletRequest req) {
        final GoogleIdToken idToken = (GoogleIdToken) req.getSession().getAttribute(OAuthConst.SESSION_KEY_ID_TOKEN);
        return idToken;
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
