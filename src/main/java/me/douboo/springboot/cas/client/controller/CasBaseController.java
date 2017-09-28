package me.douboo.springboot.cas.client.controller;

import javax.servlet.http.HttpServletRequest;

import me.douboo.springboot.cas.client.entity.CasUser;
import me.douboo.springboot.cas.client.exceptions.SessionTimeoutException;
import me.douboo.springboot.cas.client.util.CasUtils;

public class CasBaseController {

	protected Long getCurrentUserId(HttpServletRequest request) throws SessionTimeoutException {
		return getCurrentUser(request).getId();
	}

	protected CasUser getCurrentUser(HttpServletRequest request) throws SessionTimeoutException {
		CasUser user = CasUtils.getCurrentUser(request);
		if (null != user) {
			return user;
		}
		throw new SessionTimeoutException();
	}

}
