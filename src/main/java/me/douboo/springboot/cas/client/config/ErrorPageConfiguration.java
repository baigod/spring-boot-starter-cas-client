package me.douboo.springboot.cas.client.config;

import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

@Configuration
public class ErrorPageConfiguration {

	static final String PAGE_PREFIX = "/error/";

	@Bean
	public EmbeddedServletContainerCustomizer containerCustomizer() {
		return new MyCustomizer();
	}

	private static class MyCustomizer implements EmbeddedServletContainerCustomizer {

		@Override
		public void customize(ConfigurableEmbeddedServletContainer container) {
			container.addErrorPages(errorPages(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN, HttpStatus.NOT_FOUND,
					HttpStatus.INTERNAL_SERVER_ERROR, HttpStatus.BAD_GATEWAY, HttpStatus.GATEWAY_TIMEOUT));
		}

		private ErrorPage[] errorPages(HttpStatus... status) {
			ErrorPage[] errorPages = new ErrorPage[status.length];
			for (int i = 0; i < errorPages.length; i++) {
				errorPages[i] = new ErrorPage(status[i], PAGE_PREFIX + status[i].value());
			}
			return errorPages;
		}

	}
}
