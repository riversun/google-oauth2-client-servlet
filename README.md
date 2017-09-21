# Overview

google-oauth2-client-servlet is a library for OAuth2/OpenId connect.

You can easily develop your servlet-based webapp using google OAuth2/OpenId connect.

It is licensed under [MIT](https://opensource.org/licenses/MIT).

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.riversun/google-oauth2-client-servlet/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.riversun/google-oauth2-client-servlet)

# Quick start

This example code can retrieve a user's Google userInfo after OAuth2-flow.

## implement Servlet which can login with Google.

Implement the OAuth 2 / OpenId connect process simply by inheriting OAuthCallbackServlet and OAuthFilter and returning simple settings like this.

You can clone/download this example from here.  
https://github.com/riversun/google-login-servlet-example-simple.git

------

### (1/4)implement callback servlet which extends OAuthCallbackServlet
- should override getAuthRedirectUrl() returns OAuthCallbackServlet's URL
- override saveRefreshTokenFor()/loadRefreshTokenFor() to persist refresh_token if you want.

```java
@SuppressWarnings("serial")
public class MyOAuthCallbackServlet extends OAuthCallbackServlet {

    static final String OAUTH2_CALLBACK_URL = "http://localhost:8080/callback";

    @Override
    protected String getAuthRedirectUrl() {
        // Should return url of callback servlet(this servlet)
        return OAUTH2_CALLBACK_URL;
    }
}
```

------


### (2/4)implement servlet filter which extends OAuthFilter.

- should override getAuthRedirectUrl() returns URL of MyOAuthCallbackServlet
- should override getScopes() returns OAuth2 SCOPE

```java
public class MyOAuthFilter extends OAuthFilter {

	@Override
	protected String getAuthRedirectUrl() {
		return MyOAuthCallbackServlet.OAUTH2_CALLBACK_URL;
	}

	@Override
	protected boolean isAuthenticateEverytime() {
		// If true, execute OAuth2-flow every time<br>
		return true;
	}

	// Return OAuth2 scope you want to be granted to by users
	@Override
	protected List<String> getScopes() {

		final String OAUTH2_SCOPE_MAIL = "email";
		final String OAUTH2_SCOPE_USERINFO_PROFILE = "https://www.googleapis.com/auth/userinfo.profile";

		return Arrays.asList(OAUTH2_SCOPE_MAIL, OAUTH2_SCOPE_USERINFO_PROFILE);

	}

}

```

------


### (3/4)implement Main servlet which can access Google Services with OAuth2

- **credential** which contains access_token and refresh_token will be stored in the HTTPSession.You can obtain via wrapper class.  
**OAuthSession.getInstance().createCredential(req)**

- **unique userId** can be obtained via wrapper class.  
**OAuthSession.getInstance().getUserId(req);**

```java
public class MyAppServlet extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		resp.setContentType("text/html; charset=UTF-8");
		// Get credential including access_token
		GoogleCredential credential = OAuthSession.getInstance().createCredential(req);
		// Get unique userId
		String userId = OAuthSession.getInstance().getUserId(req);

		Oauth2 oauth2 = new Oauth2.Builder(
				new com.google.api.client.http.javanet.NetHttpTransport(),
				new com.google.api.client.json.jackson2.JacksonFactory(),
				credential).build();

		// Get userInfo using credential
		Userinfoplus userInfo = oauth2.userinfo().get().execute();
		final PrintWriter out = resp.getWriter();
		// Show result
		out.println("<html><body>You are already logged in to Google.");
		out.println("<br>");
		out.println("<b>OAuth2/OpenId connect result</b><br>");
		out.println("userId=" + userId);
		out.println("userInfo=" + userInfo);

		out.close();

	}

}
```

------


### (4/4)Run on local jetty

- Add OAuth2callback servlet for "/callback"
- Add OAuthFilter for "/app/*"
- Add MainServlet for "/app/main"
- The main servlet is called after passing the OAuthFilter

```java
public class MyAppMain {

	public static void main(String[] args) throws IOException {
		startServer();
	}

	public static void startServer() {

		Server jettyServer = new Server(8080);

		ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.SESSIONS);

		ctx.addServlet(new ServletHolder(new MyOAuthCallbackServlet()), "/callback");

		ctx.addFilter(MyOAuthFilter.class, "/app/*",
				EnumSet.of(DispatcherType.INCLUDE, DispatcherType.REQUEST));

		ctx.addServlet(new ServletHolder(new MyAppServlet()), "/app/main");

		jettyServer.setHandler(ctx);

		try {
			jettyServer.start();
			jettyServer.join();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
```

------


### Add Maven dependency

```xml
<dependency>
    <groupId>org.eclipse.jetty</groupId>
    <artifactId>jetty-server</artifactId>
    <version>9.4.4.v20170414</version>
  </dependency>

  <dependency>
    <groupId>org.eclipse.jetty</groupId>
    <artifactId>jetty-webapp</artifactId>
    <version>9.4.4.v20170414</version>
  </dependency>

  <dependency>
    <groupId>org.riversun</groupId>
    <artifactId>google-oauth2-client-servlet</artifactId>
    <version>0.8.2</version>
  </dependency>
```

------

### Create client_secret.json and put it in the top of src folder

Create credential if you have not created it.  
1. open https://console.cloud.google.com/  
    1. select API & services
    1. Credentials
    1. Create credentials
    1. OAuth Client Id
    1. Web application
    1. Add authorized redirect url to http://localhost:8080 (for testing)
    1. click Save
    <img src="https://riversun.github.io/img/goauth2/lib_oauth2_callback_url.png">

1. download **client_secret.json" from https://console.cloud.google.com/apis/credentials
<img src="https://riversun.github.io/img/goauth2/lib_oauth2_download.png">

1. Rename downloaded file to **client_secret.json** and save it on the top of the src folder.

------


### Run

run MyAppMain.java

<img src="https://riversun.github.io/img/goauth2/lib_oauth2_example01.png" width="100%">

------

# OAuth2 flow and how this library works

<img src="https://riversun.github.io/img/goauth2/lib_oauth2_preview.png">

------

# More practical examples

In the above example you know authentication/authorization and application login are inseparable.

To create a practical web application,  
It is necessary to separate application level login and OAuth2-flow.  
And it is necessary to design separately the part of authentication "who are you?"  
and the part of authorization to grant permission (to the API).

## download / clone
I would like to introduce an example of separating app login and OAuth.You can clone and easy to run it.

https://github.com/riversun/google-login-servlet-example-on-jetty.git

## run

run com.example.MyAppMain

**Example app flow**

1. Click **Login with Google**
1. authentication (with id/password for Google Account)
1. authorization (with Google's consent screen/permission check)
1. login to app with uniqueId provided by Google
1. Get userInfo from Google with access_token(refresh_token)
1. Click **Log out** to forget OAuth2 state and set app state "logout"

<img src="https://riversun.github.io/img/goauth2/lib_oauth2_example02a.png">

<img src="https://riversun.github.io/img/goauth2/lib_oauth2_example02b.png">
