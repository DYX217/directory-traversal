# directory-traversal
Introduce the incorrect access control vulnerabilities in favorites-web project.

favorites-web, an open source cloud collection project with 4.8k stars on GitHub, has a directory traversal vulnerability in the file [SecurityFilter.java](https://github.com/cloudfavorites/favorites-web/blob/master/app/src/main/java/com/favorites/comm/filter/SecurityFilter.java). In the Spring Boot service, an important role of the filter layer is permission control, that is, to verify permissions before the request reaches the target resource to ensure that only authorized users can access specific resources.


## version
Favorites-web Project v1.3.0

## Vulnerability causes
The main function of SecurityFilter.java to implement permission control is in the dofilter function.

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
