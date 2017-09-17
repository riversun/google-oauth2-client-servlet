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
import java.io.InputStream;
import java.io.InputStreamReader;

import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;

/**
 * A class that gets/sets clientSecrets like "client_secret.json" downloaded
 * from developer console<br>
 * <p>
 * Default clientSecrets path is "/client_secret.json"<br>
 * If you want to specify path/filename of clientSecrets,call
 * {@link OAuthSecrets#setClientSecrets} before OAuth2-flow stars.
 * </p>
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 */
public class OAuthSecrets {

    private static GoogleClientSecrets sGoogleClientSecrets = null;

    public static void setClientSecrets(GoogleClientSecrets googleClientSecrets) {
        sGoogleClientSecrets = googleClientSecrets;
    }

    public static void setClientSecrets(String relativeFilePath) throws IOException {
        final InputStream is = OAuthCommon.class.getResourceAsStream(relativeFilePath);
        sGoogleClientSecrets = GoogleClientSecrets.load(OAuthCommon.JSON_FACTORY, new InputStreamReader(is));
    }

    public static GoogleClientSecrets getClientSecrets() throws IOException {
        if (sGoogleClientSecrets == null) {
            setClientSecrets("/client_secret.json");
        }
        return sGoogleClientSecrets;
    }
}
