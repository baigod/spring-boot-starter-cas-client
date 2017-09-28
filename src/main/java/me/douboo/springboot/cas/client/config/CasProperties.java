package me.douboo.springboot.cas.client.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Created by luheng on 2017/8/14.
 */
@ConfigurationProperties(prefix = "cas")
public class CasProperties {

	private Server server = new Server();
	private Client client = new Client();

	public Server getServer() {
		return server;
	}

	public void setServer(Server server) {
		this.server = server;
	}

	public Client getClient() {
		return client;
	}

	public void setClient(Client client) {
		this.client = client;
	}

	public static class Server {
		private String url;

		private String loginUrl;

		private String logoutUrl;

		public String getUrl() {
			return url;
		}

		public void setUrl(String url) {
			this.url = url;
		}

		public String getLoginUrl() {
			return loginUrl;
		}

		public void setLoginUrl(String loginUrl) {
			this.loginUrl = loginUrl;
		}

		public String getLogoutUrl() {
			return logoutUrl;
		}

		public void setLogoutUrl(String logoutUrl) {
			this.logoutUrl = logoutUrl;
		}
	}

	public static class Client {
		private String url;

		private String loginUrl = "/login";

		private String logoutUrl = "/logout";

		private String pattern = "/|/logout";

		public String getUrl() {
			return url;
		}

		public void setUrl(String url) {
			this.url = url;
		}

		public String getLoginUrl() {
			return loginUrl;
		}

		public void setLoginUrl(String loginUrl) {
			this.loginUrl = loginUrl;
		}

		public String getLogoutUrl() {
			return logoutUrl;
		}

		public void setLogoutUrl(String logoutUrl) {
			this.logoutUrl = logoutUrl;
		}

		public String getPattern() {
			return pattern;
		}

		public void setPattern(String pattern) {
			this.pattern = pattern;
		}

	 

	}

}
