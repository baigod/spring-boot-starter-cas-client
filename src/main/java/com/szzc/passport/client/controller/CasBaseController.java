package com.szzc.passport.client.controller;

import javax.servlet.http.HttpServletRequest;

import com.szzc.passport.client.entity.CasUser;
import com.szzc.passport.client.exceptions.SessionTimeoutException;
import com.szzc.passport.client.util.CasUtils;

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
