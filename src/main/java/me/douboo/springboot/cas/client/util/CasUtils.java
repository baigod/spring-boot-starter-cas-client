package me.douboo.springboot.cas.client.util;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.util.CollectionUtils;

import me.douboo.springboot.cas.client.entity.CasUser;

public class CasUtils {

	public static CasUser getCurrentUser(HttpServletRequest request) {
		CasAuthenticationToken token = (CasAuthenticationToken) request.getUserPrincipal();
		if (null != token) {
			Assertion assertion = token.getAssertion();
			if (null != assertion) {
				AttributePrincipal principal = assertion.getPrincipal();
				if (null != principal) {
					Map<String, Object> attributes = principal.getAttributes();
					return parseAttributes(attributes);
				}
			}
		}
		return null;
	}

	public static CasUser parseAttributes(Map<String, Object> attributes) {
		if (!CollectionUtils.isEmpty(attributes)) {
			Object userId = attributes.get("id");
			if (null != userId) {
				CasUser user = new CasUser();
				user.setId(Long.parseLong(userId.toString()));
				user.setEmail(String.valueOf(attributes.get("email")));// email
				user.setLastLoginDate(String.valueOf(attributes.get("lastLoginDate")));// 最后一次登录时间
				user.setPhone(String.valueOf(attributes.get("phone")));// 手机号码
				user.setAreaCode(String.valueOf(attributes.get("areaCode")));// 手机号区号
				return user;
			}
		}
		return null;
	}

}
