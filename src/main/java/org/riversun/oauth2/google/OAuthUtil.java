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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 *
 */
public final class OAuthUtil {
    private static final Logger LOGGER = Logger.getLogger(OAuthUtil.class.getName());

    // SCOPE
    static final List<String> SCOPES = new CopyOnWriteArrayList<String>();

    // Thread-safed
    static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

    // Thread-safed
    static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    static final GoogleAuthorizationCodeFlow createFlow() throws IOException {
        return new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT,
                JSON_FACTORY,
                OAuthSecrets.getClientSecrets(),
                SCOPES)
                        .build();
    }

    // Thread-safed
    public static final GoogleCredential createCredential(String accessToken, String refreshToken) throws IOException {

        LOGGER.fine("accessToken=" + accessToken + " refreshToken=" + refreshToken);

        final GoogleCredential credential = new GoogleCredential.Builder()

                .setTransport(OAuthUtil.HTTP_TRANSPORT)
                .setJsonFactory(OAuthUtil.JSON_FACTORY)
                .setClientSecrets(OAuthSecrets.getClientSecrets())
                .build()
                .setAccessToken(accessToken)
                // If refreshToken is set, new access token will be
                // retrieved(renewed) properly
                // even if the old access token expires.
                .setRefreshToken(refreshToken);
        return credential;
    }
}
