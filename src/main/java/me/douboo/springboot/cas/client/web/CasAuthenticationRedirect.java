package me.douboo.springboot.cas.client.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.util.StringUtils;

/**
 * 自定义类：CasAuthenticationRedirect
 * 
 * @author Administrator
 *
 */
public class CasAuthenticationRedirect extends CasAuthenticationEntryPoint {

	private String serviceUrlBak = null;
	private static final String DEFAULT_TARGET_PARAMETER = "service";

	@Override
	protected String createServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
		if (serviceUrlBak == null)
			serviceUrlBak = getServiceProperties().getService();
		if (serviceUrlBak != null) {
			String ctx = request.getContextPath();
			String queryString = request.getQueryString();
			String requestURI = request.getRequestURI();
			requestURI = requestURI.substring(requestURI.indexOf(ctx) + ctx.length(), requestURI.length());
			String serviceUrl = "";
			if (!requestURI.equals("/") && requestURI.length() > 0) {
				serviceUrl = "?" + DEFAULT_TARGET_PARAMETER;
				serviceUrl += "=" + requestURI;
				if (!StringUtils.isEmpty(queryString)) {
					serviceUrl += "?" + queryString;
				}
			}
			getServiceProperties().setService(null);
		}
		return super.createServiceUrl(request, response);
	}
}