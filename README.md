# directory-traversal
Introduce the incorrect access control vulnerabilities in favorites-web project.

favorites-web, an open source cloud collection project with 4.8k stars on GitHub, has a directory traversal vulnerability in the file [SecurityFilter.java](https://github.com/cloudfavorites/favorites-web/blob/master/app/src/main/java/com/favorites/comm/filter/SecurityFilter.java). In the Spring Boot service, an important role of the filter layer is permission control, that is, to verify permissions before the request reaches the target resource to ensure that only authorized users can access specific resources.


## version
Favorites-web Project v1.3.0

## Vulnerability causes
The main function of SecurityFilter.java to implement permission control is in the doFilter function.

```java
public void doFilter(ServletRequest srequest, ServletResponse sresponse, FilterChain filterChain)
			throws IOException, ServletException {
	// TODO Auto-generated method stub
	HttpServletRequest request = (HttpServletRequest) srequest;
	String uri = request.getRequestURI();
	if (request.getSession().getAttribute(Const.LOGIN_SESSION_KEY) == null) {
		Cookie[] cookies = request.getCookies();
		if (containsSuffix(uri)  || GreenUrlSet.contains(uri) || containsKey(uri)) {
			logger.debug("don't check  url , " + request.getRequestURI());
			filterChain.doFilter(srequest, sresponse);
			return;
		}else if (cookies!=null) {
			boolean flag = true;
			for (int i = 0; i < cookies.length; i++) {
				Cookie cookie = cookies[i];
				if (cookie.getName().equals(Const.LOGIN_SESSION_KEY)) {
					if(StringUtils.isNotBlank(cookie.getValue())){
						flag = false;
					}else{
						break;
					}
					String value = getUserId(cookie.getValue());
					Long userId = 0l;
					if (userRepository == null) {
						BeanFactory factory = WebApplicationContextUtils.getRequiredWebApplicationContext(request.getServletContext());
						userRepository = (UserRepository) factory.getBean("userRepository");
					}
					if(StringUtils.isNotBlank(value)){
						userId = Long.parseLong(value);
					}
					User user = userRepository.findById((long)userId);
					String html = "";
					if(null == user){
						html = "<script type=\"text/javascript\">window.location.href=\"_BP_login\"</script>";
					}else{
						logger.info("userId :" + user.getId());
						request.getSession().setAttribute(Const.LOGIN_SESSION_KEY, user);
						String referer = this.getRef(request);
						if(referer.indexOf("/collect?") >= 0 || referer.indexOf("/lookAround") >= 0){
							filterChain.doFilter(srequest, sresponse);
							return;
						}else{
							html = "<script type=\"text/javascript\">window.location.href=\"_BP_\"</script>";
						}
					}
					html = html.replace("_BP_", Const.BASE_PATH);
					sresponse.getWriter().write(html);
					/**
					 * HttpServletResponse response = (HttpServletResponse) sresponse;
					 response.sendRedirect("/");
					*/
				}
			}
			if(flag){
				//跳转到登陆页面
				String referer = this.getRef(request);
				logger.debug("security filter, deney, " + request.getRequestURI());
				String html = "";
				if(referer.contains("/collect?") || referer.contains("/lookAround")){
					html = "<script type=\"text/javascript\">window.location.href=\"_BP_login\"</script>";
				}else{
					html = "<script type=\"text/javascript\">window.location.href=\"_BP_index\"</script>";
				}
				html = html.replace("_BP_", Const.BASE_PATH);
				sresponse.getWriter().write(html);
			}
		}else{
			//跳转到登陆页面
			String referer = this.getRef(request);
			logger.debug("security filter, deney, " + request.getRequestURI());
			String html = "";
			if(referer.contains("/collect?") || referer.contains("/lookAround")){
				html = "<script type=\"text/javascript\">window.location.href=\"_BP_login\"</script>";
			}else{
				html = "<script type=\"text/javascript\">window.location.href=\"_BP_index\"</script>";
			}
			html = html.replace("_BP_", Const.BASE_PATH);
			sresponse.getWriter().write(html);
			//	HttpServletResponse response = (HttpServletResponse) sresponse;
			//response.sendRedirect("/");

		}
	}else{
		filterChain.doFilter(srequest, sresponse);
	}
}
```

This function uses the unsafe method `getRequestURI` to obtain user requests, which does not process directory operations such as './' and '../'. Then this function uses `containsSuffix`, `GreenUrlSet.contains` and `containsKey` match the authentication-free whitelist. If one of these three functions returns true, no identity verification is performed. 

The `containsKey` function use `contains` and `startsWith` to match requests that contain the specified string or start with the specified string. If the match is successful, it returns `true` and `doFilter` will not perform identity verification.

```java
private boolean containsKey(String url) {

		if (url.contains("/media/")
				// /admin /login/../admin
				|| url.contains("/login")||url.contains("/user/login")
				|| url.contains("/register")||url.contains("/user/regist")||url.contains("/index")
				|| url.contains("/forgotPassword")||url.contains("/user/sendForgotPasswordEmail")
				|| url.contains("/newPassword")||url.contains("/user/setNewPassword")
				|| (url.contains("/collector") && !url.contains("/collect/detail/"))
				|| url.contains("/collect/standard/")||url.contains("/collect/simple/")
				|| url.contains("/user")||url.contains("/favorites")||url.contains("/comment")
				|| url.contains("/lookAround")
				|| url.startsWith("/user/")
				|| url.startsWith("/feedback")
				|| url.startsWith("/standard/")) {
			return true;
		} else {
			return false;
		}
}
```

We can use directory traversal to bypass identity verification. For example, when the `url.contains("/login")` condition is met, identity authentication can be bypassed. Therefore, when we want to access an authentication interface such as `/auth`, we can bypass authentication by accessing `/login/../auth`.

The codes of the other two functions are as follows. Since they are not involved in this exploit, they will not be repeated here.

The `containsSuffix` function is used to determine whether the path is a static resource with a specified suffix.

```java
private boolean containsSuffix(String url) {
		if (url.endsWith(".js")
				|| url.endsWith(".css")
				|| url.endsWith(".jpg")
				|| url.endsWith(".gif")
				|| url.endsWith(".png")
				|| url.endsWith(".html")
				|| url.endsWith(".eot")
				|| url.endsWith(".svg")
				|| url.endsWith(".ttf")
				|| url.endsWith(".woff")
				|| url.endsWith(".ico")
				|| url.endsWith(".woff2")) {
			return true;
		} else {
			return false;
		}
}
```

`GreenUrlSet.contains` is used to determine whether the path is in the specified whitelist.

```java
public void init(FilterConfig arg0) throws ServletException {
		// TODO Auto-generated method stub
		GreenUrlSet.add("/login");
		GreenUrlSet.add("/register");
		GreenUrlSet.add("/index");
		GreenUrlSet.add("/forgotPassword");
		GreenUrlSet.add("/newPassword");
		GreenUrlSet.add("/tool");
}
```

## Vulnerability reproduce

First, we find an interface that requires authentication to access, `/export`. The function corresponding to this interface is to export favorites.

Then, we tried to access this endpoint by Postman without authentication information. We can see that due to the lack of authentication information, the request is redirected to index.html.
![normal access](blob:https://github.com/2ca9838e-bbca-41a5-b987-89bd5c9ec1e0)

After that, also without authentication information, we try to access the `/login/../export` interface. We can see that the access is successful.
![directory traversal](blob:https://github.com/335b19fd-e372-4d41-b25b-c2c073e55497)

## Impact

Users can use directory traversal to gain unauthorized access to the interface.


