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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Common helper methods for servlet
 * 
 * @author Tom Misawa (riversun.org@gmail.com)
 */
@SuppressWarnings("serial")
public class OAuthBaseServlet extends HttpServlet {

	@Retention(RetentionPolicy.RUNTIME)
	public @interface CORS {

		public String allowFrom();

		public boolean allowCredentials();

	}

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		final CORS cors = this.getClass().getAnnotation(CORS.class);

		if (cors != null) {

			final String allowFrom = cors.allowFrom();

			if (allowFrom != null && !allowFrom.isEmpty()) {
				setAccessControlAllowOrigin(resp, allowFrom);
			}

			boolean allowCredentials = cors.allowCredentials();
			setAccessControlAllowCredentials(resp, allowCredentials);
		}

		super.service(req, resp);

	}

	protected String asString(HttpServletRequest req, String parameterName) {
		return req.getParameter(parameterName);
	}

	public String asString(HttpServletRequest req) {

		final StringBuffer sb = new StringBuffer();

		String line = null;

		try {
			BufferedReader reader = req.getReader();
			while ((line = reader.readLine()) != null) {
				sb.append(line);
			}
		} catch (Exception e) {
		}
		return sb.toString();
	}

	protected Long asLong(HttpServletRequest req, String parameterName) {
		Long retVal = null;

		try {
			retVal = Long.parseLong(asString(req, parameterName));
		} catch (Exception e) {

		}
		return retVal;

	}

	protected Integer asInteger(HttpServletRequest req, String parameterName) {
		Integer retVal = null;

		try {
			retVal = Integer.parseInt(asString(req, parameterName));
		} catch (Exception e) {
		}
		return retVal;

	}

	protected void requestScope(HttpServletRequest req, String name, Object value) {
		req.setAttribute(name, value);
	}

	protected Object requestScope(HttpServletRequest req, String name) {
		return req.getAttribute(name);
	}

	protected void sessionScope(HttpServletRequest req, String name, Object value) {
		HttpSession session = req.getSession(true);
		if (value != null) {
			session.setAttribute(name, value);
		} else {
			session.removeAttribute(name);
		}
	}

	protected Object sessionScope(HttpServletRequest req, String name) {
		HttpSession session = req.getSession(true);
		return session.getAttribute(name);
	}

	public void setContentTypeTo_JSON_UTF8(HttpServletResponse resp) {
		setContentType(resp, "application/json; charset=UTF-8");
	}

	protected String getRemoteHost(HttpServletRequest req) {
		return req.getRemoteHost();
	}

	public void setContentTypeTo_HTML_UTF8(HttpServletResponse resp) {
		setContentType(resp, "text/html; charset=UTF-8");
	}

	public void setContentTypeTo_XML_UTF8(HttpServletResponse resp) {
		setContentType(resp, "application/xml; charset=UTF-8");
	}

	protected void dispatch(HttpServletRequest req, HttpServletResponse resp, String fowardToPath) throws ServletException, IOException {
		RequestDispatcher dispatcher = req.getRequestDispatcher(fowardToPath);
		dispatcher.forward(req, resp);
	}

	public void setContentType(HttpServletResponse resp, String contentType) {
		resp.setContentType(contentType);
	}

	/**
	 * Returns text
	 * 
	 * @param text
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void returnAsText(HttpServletResponse resp, String text) throws ServletException, IOException {
		final PrintWriter out = resp.getWriter();
		out.println(text);
		out.close();
	}

	/**
	 * Set CORS policy
	 * 
	 * @param value
	 *            specify like "*","https://xxxxxx.com"
	 */
	protected void setAccessControlAllowOrigin(HttpServletResponse resp, String value) {
		resp.addHeader("Access-Control-Allow-Origin", value);
		resp.addHeader("Access-Control-Allow-Headers", "Content-Type");
	}

	/**
	 * Enable Cookie while CORS connection
	 * 
	 * @param enabled
	 */
	protected void setAccessControlAllowCredentials(HttpServletResponse resp, boolean enabled) {
		if (enabled) {
			resp.addHeader("Access-Control-Allow-Credentials", String.valueOf(enabled));
		}
	}

	protected void redirect(HttpServletResponse resp, String redirectToPath) throws ServletException, IOException {

		String ret = "";
		if (redirectToPath.startsWith("/")) {
			ret = removeHead(redirectToPath, 1);
		}
		resp.sendRedirect(ret);
	}

	private String removeHead(String str, int cnt) {
		final StringBuilder sb = new StringBuilder(str);
		try {
			sb.delete(0, cnt);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return sb.toString();

	}

	protected void returnAsHtml(HttpServletResponse resp, String html) throws ServletException, IOException {
		setContentTypeTo_HTML_UTF8(resp);

		final PrintWriter out = resp.getWriter();

		out.println(html);
		out.close();
	}

	protected void returnAsJS(HttpServletResponse resp, String html) throws ServletException, IOException {
		setContentType(resp, "application/javascript; charset=UTF-8");

		final PrintWriter out = resp.getWriter();

		out.println(html);
		out.close();
	}

	/**
	 * Returns nothing
	 * 
	 * @throws IOException
	 */
	protected void returnNothing(HttpServletResponse resp) throws IOException {
		setContentTypeTo_JSON_UTF8(resp);

		final PrintWriter out = resp.getWriter();
		out.close();
	}

	/**
	 * Add cookie to request
	 * 
	 * @param cookieKey
	 * @param cookieValue
	 * @param maxAge
	 */
	protected void addCookie(HttpServletResponse resp, String name, String value, int maxAge) {
		Cookie cookie = new Cookie(name, value);
		cookie.setMaxAge(maxAge);
		cookie.setSecure(true);
		resp.addCookie(cookie);
	}

	public String getCookie(HttpServletRequest req, String name) {
		String result = null;

		final Cookie[] cookies = req.getCookies();

		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (name.equals(cookie.getName())) {
					result = cookie.getValue();
					break;
				}
			}
		}

		return result;
	}

}
