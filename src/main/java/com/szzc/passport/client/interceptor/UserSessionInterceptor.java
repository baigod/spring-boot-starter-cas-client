package com.szzc.passport.client.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.szzc.passport.client.constants.Constants;
import com.szzc.passport.client.entity.CasUser;
import com.szzc.passport.client.util.CasUtils;

public class UserSessionInterceptor extends HandlerInterceptorAdapter {

	private final Logger logger = LoggerFactory.getLogger(UserSessionInterceptor.class);

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		HttpSession session = request.getSession(false);
		if (null != session)
			logger.info(session.getId());

		CasUser user = CasUtils.getCurrentUser(request);
		if (user == null) {
			return true;
		}
		session.setAttribute(Constants.SESSION_USER, user);
		return true;
	}

}
