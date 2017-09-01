package com.szzc.passport.client;

import java.net.Inet4Address;
import java.util.HashSet;

import org.jasig.cas.client.proxy.MemcachedBackedProxyGrantingTicketStorageImpl;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;
import com.szzc.passport.client.session.ClusterSingleSignOutFilter;
import com.szzc.passport.client.session.ClusterSingleSignOutHandler;
import com.szzc.passport.client.session.ConCurrentHashMapBackedSessionMappingStorage;
import com.szzc.spring.boot.starter.zookeeper.EnableZookeeper;
import com.szzc.spring.boot.starter.zookeeper.ZookeeperUtils;

/**
 * 配置CAS 
 * @author Created by luheng on 2017/2/17.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties(CasProperties.class)
@EnableZookeeper
@EnableScheduling
public class CasConfiguration extends WebSecurityConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(CasConfiguration.class);
	@Autowired
	private ZookeeperUtils zookeeperUtils;

	@Value("${spring.application.name:unknowApplicationName}")
	private String applicationName;

	@Value("${server.port:0}")
	private String serverPort;

	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
		ClusterSingleSignOutHandler.currentNode = Inet4Address.getLocalHost().getHostAddress() + ":" + serverPort;
	}

	// 注册当前服务的ip到zk
	@Scheduled(cron = "*/10 * * * * ?")
	public void checkNode() {
		try {
			String path = "/passport-client-cluster/" + applicationName;
			String node = ClusterSingleSignOutHandler.currentNode;
			if (!zookeeperUtils.exists(path, node)) {
				this.zookeeperUtils.createNode(path, node);
				logger.debug("节点{}/{}创建成功", path, node);
			}
			ClusterSingleSignOutHandler.clusters = new HashSet<String>(this.zookeeperUtils.listNodesByPath(path));
			logger.debug("当前路径下共有{}个节点:{}", ClusterSingleSignOutHandler.clusters.size(),
					JSONObject.toJSONString(ClusterSingleSignOutHandler.clusters));

		} catch (Exception e) {
			logger.warn(e.getMessage());
		}
	}

	@Autowired
	private CasProperties casProperties;

	/* 定义认证用户信息获取来源，密码校验规则等 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(casAuthenticationProvider());
	}

	/* 定义安全策略 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()// 配置安全策略
				.antMatchers(casProperties.getClient().getPattern().split("\\|")).authenticated()// 定义需要验证的请求
				.anyRequest().permitAll()// 其余的不需要验证
				.and().logout().permitAll()// 定义logout不需要验证
				.and().formLogin();// 使用form表单登录

		http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint()).and()
				.addFilter(casAuthenticationFilter()).addFilterBefore(casLogoutFilter(), LogoutFilter.class)
				.addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class);

		http.csrf().disable(); // 禁用CSRF
	}

	/* 认证的入口 */
	@Bean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
		CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
		casAuthenticationEntryPoint.setLoginUrl(casProperties.getServer().getLoginUrl());
		casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
		return casAuthenticationEntryPoint;
	}

	/* 指定service相关信息 */
	@Bean
	public ServiceProperties serviceProperties() {
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService(casProperties.getClient().getUrl() + casProperties.getClient().getLoginUrl());
		serviceProperties.setAuthenticateAllArtifacts(true);
		return serviceProperties;
	}

	/* CAS认证过滤器 */
	@Bean
	public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
		CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
		casAuthenticationFilter.setAuthenticationManager(authenticationManager());
		casAuthenticationFilter.setFilterProcessesUrl(casProperties.getClient().getLoginUrl());
		return casAuthenticationFilter;
	}

	/* cas 认证 Provider */
	@Bean
	public CasAuthenticationProvider casAuthenticationProvider() {
		CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
		casAuthenticationProvider.setAuthenticationUserDetailsService(casUserDetailsService());
		casAuthenticationProvider.setServiceProperties(serviceProperties());
		casAuthenticationProvider.setTicketValidator(cas20ServiceTicketValidator());
		casAuthenticationProvider.setKey("casAuthenticationProviderKey");
		return casAuthenticationProvider;
	}

	/* 用户自定义的AuthenticationUserDetailsService */
	@Bean
	public AuthenticationUserDetailsService<CasAssertionAuthenticationToken> casUserDetailsService() {
		return new CasUserDetailsService();
	}

	@Value("${memcached.servers:}")
	private String memcachedServers;

	@Bean
	public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
		Cas20ServiceTicketValidator cas20ServiceTicketValidator = new Cas20ServiceTicketValidator(
				casProperties.getServer().getUrl());
		if (!StringUtils.isEmpty(memcachedServers)) {
			cas20ServiceTicketValidator.setProxyGrantingTicketStorage(
					new MemcachedBackedProxyGrantingTicketStorageImpl(memcachedServers.split(",")));
		}
		return cas20ServiceTicketValidator;
	}

	/* 单点登出过滤器 */
	@Bean
	public ClusterSingleSignOutFilter singleSignOutFilter() {
		ClusterSingleSignOutFilter singleSignOutFilter = new ClusterSingleSignOutFilter();
		singleSignOutFilter.setCasServerUrlPrefix(casProperties.getServer().getUrl());
		singleSignOutFilter.setIgnoreInitConfiguration(true);
		singleSignOutFilter.setSessionMappingStorage(new ConCurrentHashMapBackedSessionMappingStorage());
		return singleSignOutFilter;
	}

	/* 请求单点退出过滤器 */
	@Bean
	public LogoutFilter casLogoutFilter() {
		LogoutFilter logoutFilter = new LogoutFilter(casProperties.getServer().getLogoutUrl(),
				new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl(casProperties.getClient().getLogoutUrl());
		return logoutFilter;
	}

	/* session 销毁监听,不过好像没屌用 */
	@Bean
	public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> ssoListenerRegistrationBean() {
		// SingleSignOutHttpSessionListener实现了javax.servlet.http.HttpSessionListener接口，用于监听session销毁事件
		SingleSignOutHttpSessionListener logoutListener = new SingleSignOutHttpSessionListener();
		// 通过ServletListenerRegistrationBean获取控制加入相关的监听
		ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> registration = new ServletListenerRegistrationBean<>();
		registration.setListener(logoutListener);
		registration.addInitParameter("casServerLogoutUrl", casProperties.getClient().getLogoutUrl());
		registration.setName("SingleSignOutHttpSessionListener");
		registration.setEnabled(true);
		return registration;
	}
}
