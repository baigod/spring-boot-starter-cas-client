package me.douboo.springboot.cas.client.config;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.web.servlet.error.ErrorViewResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;

@Configuration
public class ErrorPageConfiguration {

	static final String PAGE_PREFIX = "/error/";

	@Bean
	public ErrorViewResolver containerCustomizer() {
		return new MyErrorViewResolver();
	}

	private static class MyErrorViewResolver implements ErrorViewResolver {

		@Override
		public ModelAndView resolveErrorView(HttpServletRequest request, HttpStatus status, Map<String, Object> model) {
			int errorStatus = status.value();
			if (status == HttpStatus.INTERNAL_SERVER_ERROR || status == HttpStatus.BAD_GATEWAY
					|| status == HttpStatus.GATEWAY_TIMEOUT) {
				errorStatus = 404;
			}
			return new ModelAndView(PAGE_PREFIX + errorStatus);
		}

	}
}
