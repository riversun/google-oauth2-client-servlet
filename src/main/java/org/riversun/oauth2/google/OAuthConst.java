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

/**
 * Constants
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 *
 */
public final class OAuthConst {

	public static final String SESSION_KEY_CREDENTIAL = "org.riversun.goauth.session_key_credential";
	public static final String SESSION_KEY_ID_TOKEN = "org.riversun.goauth.session_key_id_token";
	public static final String SESSION_KEY_UNIQUE_USER_ID = "org.riversun.goauth.session_key_payload_sub";

	static final String SESSION_KEY_OAUTH2_STATE_TOKEN = "org.riversun.goauth.session_key_oauth2_state_token";
	static final String SESSION_KEY_OAUTH2_DONE = "org.riversun.goauth.session_key_oauth2_done";
	static final String SESSION_KEY_REQUEST_URL = "org.riversun.goauth.session_key_auth_requst_url";

}
