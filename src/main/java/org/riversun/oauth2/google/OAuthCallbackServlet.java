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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;

/**
 * Callback servlet for Google OAuth2 flow<br>
 * <br>
 * When you want to revoke permission from your application. <br>
 * {@link https://security.google.com/settings/security/permissions} <br>
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 *
 */
@SuppressWarnings("serial")
public abstract class OAuthCallbackServlet extends OAuthBaseServlet {

    private static final Logger LOGGER = Logger.getLogger(OAuthCallbackServlet.class.getName());

    private final Map<String, String> mTempRefreshTokenMap = new ConcurrentHashMap<String, String>();

    /**
     * Returns redirect url
     * 
     * @return
     */
    protected abstract String getAuthRedirectUrl();

    /**
     * Save refreshToken of user.<br>
     * <br>
     * RefreshToken is recommended to be persistent rather than on - memory.
     * Override and implement this method and describe the saving process of
     * refreshToken. <br>
     * 
     * @param userId
     * @param refreshToken
     */
    protected void saveRefreshTokenFor(String userId, String refreshToken) {
        LOGGER.fine("userId=" + userId + " refreshToken=" + refreshToken);
        mTempRefreshTokenMap.put(userId, refreshToken);
    }

    /**
     * Load stored refreshToken of user.<br>
     * <br>
     * <br>
     * RefreshToken is recommended to be persistent rather than on - memory.
     * Override and implement this method and read refreshToken from the
     * persisted area. <br>
     * 
     * @param userId
     * @return
     */
    protected String loadRefreshTokenFor(String userId) {

        final String storedRefreshToken = mTempRefreshTokenMap.get(userId);

        final String refreshToken;
        if (storedRefreshToken == null) {
            refreshToken = "dummy_refresh_token";
        } else {
            refreshToken = storedRefreshToken;
        }

        LOGGER.fine("userId=" + userId + " refreshToken=" + refreshToken);
        return refreshToken;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        LOGGER.fine("");

        final String code = asString(req, "code");
        final String stateToken = asString(req, "state");

        if (code != null && stateToken != null) {
            // - required parameters( 'code' and 'state) are exist.

            LOGGER.fine("code=" + code);

            final String storedStateToken = (String) sessionScope(req, OAuthConst.SESSION_KEY_OAUTH2_STATE_TOKEN);

            if (storedStateToken != null && stateToken.equals(storedStateToken)) {
                // - stateToken matched

                LOGGER.fine("stateToken matched state=" + stateToken);

                // remove state token
                sessionScope(req, OAuthConst.SESSION_KEY_OAUTH2_STATE_TOKEN, null);
            } else {
                // - stateToken not matched

                LOGGER.warning("stateToken not matched!");

                resp.sendError(HttpServletResponse.SC_FORBIDDEN, "OAuth2 state token is invalid. stateToken=" + stateToken + " storedStateToken=" + storedStateToken);
                return;
            }

        } else {
            // - required parameters not found

            LOGGER.warning("The parameter 'code' or 'state' not found!");

            resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid parameters code=" + code + " state=" + stateToken);
            return;
        }

        final OAuthHandler oh = new OAuthHandler(getAuthRedirectUrl());

        // Retrieve token response from "code"
        final GoogleTokenResponse tokenResponse = oh.getTokenResponseFromCode(code);

        LOGGER.fine("Received tokenResponse=" + tokenResponse);
        LOGGER.fine("Received refresh_token=" + tokenResponse.getRefreshToken());

        // Parse idToken from tokenResponse
        final GoogleIdToken idToken = oh.getIdToken(tokenResponse);

        if (idToken == null) {
            throw new ServletException(new Exception("IdToken verification error"));
        }

        // idToken contains header,payload,signature.
        // Each value is stored in the format specified by RFC 7515 (JWS -JSON
        // Web Signature)

        final Payload payload = idToken.getPayload();

        sessionScope(req, OAuthConst.SESSION_KEY_ID_TOKEN, idToken);

        // An identifier for the user, unique among all Google accounts and
        // never reused.
        final String userId = payload.getSubject();

        sessionScope(req, OAuthConst.SESSION_KEY_UNIQUE_USER_ID, userId);

        LOGGER.fine("TOKEN_INFO subject(unique userId)=" + userId);

        // Get refresh_token from tokenResponse.
        // refresh_token can not be retrieved every time.
        // When accessing authorization code with access_type = "offline" ,
        // refresh_token can be retrieved only at the first access.
        final String _refreshToken = tokenResponse.getRefreshToken();

        if (_refreshToken != null) {
            // save new refreshToken
            saveRefreshTokenFor(userId, _refreshToken);
        }

        LOGGER.fine("use refresh token refreshToken=" + tokenResponse.getRefreshToken());

        final String accessToken = tokenResponse.getAccessToken();

        final GoogleCredential credential = new GoogleCredential.Builder()
                .setTransport(OAuthCommon.HTTP_TRANSPORT)
                .setJsonFactory(OAuthCommon.JSON_FACTORY)
                .setClientSecrets(OAuthSecrets.getClientSecrets())
                .build()
                .setAccessToken(accessToken)
                // If refreshToken is set, new access token will be
                // retrieved(renewed) properly
                // even if the old access token expires.
                .setRefreshToken(loadRefreshTokenFor(userId));

        sessionScope(req, OAuthConst.SESSION_KEY_CREDENTIAL, credential);
        sessionScope(req, OAuthConst.SESSION_KEY_OAUTH2_DONE, Boolean.TRUE);

        String redirectPath = (String) sessionScope(req, OAuthConst.SESSION_KEY_REDIRECT_URL_AFTER_OAUTH);

        sessionScope(req, OAuthConst.SESSION_KEY_REDIRECT_URL_AFTER_OAUTH, null);

        if (redirectPath == null || redirectPath.isEmpty()) {
            redirectPath = req.getContextPath() + "/";
        }

        LOGGER.fine("redirectPath=" + redirectPath);

        resp.sendRedirect(redirectPath);

    }

    @Override
    protected final void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        sendNotSupportedError(req, resp);
    }

    @Override
    protected final void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        sendNotSupportedError(req, resp);
    }

    @Override
    protected final void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        sendNotSupportedError(req, resp);
    }

    private final void sendNotSupportedError(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Not supported");
    }

}