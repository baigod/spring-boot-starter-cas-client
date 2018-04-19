/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package me.douboo.springboot.cas.client.session;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.zip.Inflater;

import javax.net.ssl.SSLContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * Performs CAS single sign-out operations in an API-agnostic fashion.
 *
 * @author Marvin S. Addison
 * @version $Revision$ $Date$
 * @since 3.1.12
 *
 */
public final class ClusterSingleSignOutHandler {

	private final static int DECOMPRESSION_FACTOR = 10;

	/** Logger instance */
	private final Logger logger = LoggerFactory.getLogger(getClass());

	/** Mapping of token IDs and session IDs to HTTP sessions */
	private SessionMappingStorage sessionMappingStorage = new HashMapBackedSessionMappingStorage();

	/**
	 * The name of the artifact parameter. This is used to capture the session
	 * identifier.
	 */
	private String artifactParameterName = Protocol.CAS2.getArtifactParameterName();

	/** Parameter name that stores logout request for SLO */
	private String logoutParameterName = ConfigurationKeys.LOGOUT_PARAMETER_NAME.getDefaultValue();

	/**
	 * Parameter name that stores the state of the CAS server webflow for the
	 * callback
	 */
	private String relayStateParameterName = ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getDefaultValue();

	/** The prefix url of the CAS server */
	private String casServerUrlPrefix = "";

	private boolean artifactParameterOverPost = false;

	private boolean eagerlyCreateSessions = true;

	private List<String> safeParameters;

	private final LogoutStrategy logoutStrategy = isServlet30() ? new Servlet30LogoutStrategy()
			: new Servlet25LogoutStrategy();

	/*--------cluster client begin--------*/
	/** Is clusterNodes logout request default is 0 , 0 : false , 1 : true */
	private String isClusterNodesLogoutRequestParameterName = "isClusterNodes";
	/*--------cluster client end--------*/

	public void setSessionMappingStorage(final SessionMappingStorage storage) {
		this.sessionMappingStorage = storage;
	}

	public void setArtifactParameterOverPost(final boolean artifactParameterOverPost) {
		this.artifactParameterOverPost = artifactParameterOverPost;
	}

	public SessionMappingStorage getSessionMappingStorage() {
		return this.sessionMappingStorage;
	}

	/**
	 * @param name
	 *            Name of the authentication token parameter.
	 */
	public void setArtifactParameterName(final String name) {
		this.artifactParameterName = name;
	}

	/**
	 * @param name
	 *            Name of parameter containing CAS logout request message for SLO.
	 */
	public void setLogoutParameterName(final String name) {
		this.logoutParameterName = name;
	}

	/**
	 * @param casServerUrlPrefix
	 *            The prefix url of the CAS server.
	 */
	public void setCasServerUrlPrefix(final String casServerUrlPrefix) {
		this.casServerUrlPrefix = casServerUrlPrefix;
	}

	/**
	 * @param name
	 *            Name of parameter containing the state of the CAS server webflow.
	 */
	public void setRelayStateParameterName(final String name) {
		this.relayStateParameterName = name;
	}

	public void setEagerlyCreateSessions(final boolean eagerlyCreateSessions) {
		this.eagerlyCreateSessions = eagerlyCreateSessions;
	}

	/**
	 * Initializes the component for use.
	 */
	public synchronized void init() {
		if (this.safeParameters == null) {
			CommonUtils.assertNotNull(this.artifactParameterName, "artifactParameterName cannot be null.");
			CommonUtils.assertNotNull(this.logoutParameterName, "logoutParameterName cannot be null.");
			CommonUtils.assertNotNull(this.sessionMappingStorage, "sessionMappingStorage cannot be null.");
			CommonUtils.assertNotNull(this.relayStateParameterName, "relayStateParameterName cannot be null.");
			CommonUtils.assertNotNull(this.casServerUrlPrefix, "casServerUrlPrefix cannot be null.");

			if (CommonUtils.isBlank(this.casServerUrlPrefix)) {
				logger.warn(
						"Front Channel single sign out redirects are disabled when the 'casServerUrlPrefix' value is not set.");
			}

			if (this.artifactParameterOverPost) {
				this.safeParameters = Arrays.asList(this.logoutParameterName, this.artifactParameterName);
			} else {
				this.safeParameters = Collections.singletonList(this.logoutParameterName);
			}
		}
	}

	/**
	 * Determines whether the given request contains an authentication token.
	 *
	 * @param request
	 *            HTTP reqest.
	 *
	 * @return True if request contains authentication token, false otherwise.
	 */
	private boolean isTokenRequest(final HttpServletRequest request) {
		return CommonUtils
				.isNotBlank(CommonUtils.safeGetParameter(request, this.artifactParameterName, this.safeParameters));
	}

	/**
	 * Determines whether the given request is a CAS logout request.
	 *
	 * @param request
	 *            HTTP request.
	 *
	 * @return True if request is logout request, false otherwise.
	 */
	private boolean isLogoutRequest(final HttpServletRequest request) {
		if ("POST".equalsIgnoreCase(request.getMethod())) {
			return !isMultipartRequest(request) && CommonUtils
					.isNotBlank(CommonUtils.safeGetParameter(request, this.logoutParameterName, this.safeParameters));
		}

		if ("GET".equalsIgnoreCase(request.getMethod())) {
			return CommonUtils
					.isNotBlank(CommonUtils.safeGetParameter(request, this.logoutParameterName, this.safeParameters));
		}
		return false;
	}

	/**
	 * Process a request regarding the SLO process: record the session or destroy
	 * it.
	 *
	 * @param request
	 *            the incoming HTTP request.
	 * @param response
	 *            the HTTP response.
	 * @return if the request should continue to be processed.
	 */
	public boolean process(final HttpServletRequest request, final HttpServletResponse response) {
		if (isTokenRequest(request)) {
			logger.trace("Received a token request");
			recordSession(request);
			return true;
		}

		/*--------cluster client begin--------*/
		if (isClusterNodesChannelLogoutRequest(request)) {
			logger.trace("Received a clusterNodes channel logout request");
			destroySessionFromClusterNodes(request);
			return false;
		}
		/*--------cluster client end--------*/
		
		if (isLogoutRequest(request)) {
			logger.trace("Received a logout request");
			destroySession(request);
			return false;
		}
		logger.trace("Ignoring URI for logout: {}", request.getRequestURI());
		return true;
	}

	/*--------cluster client begin--------*/
	/**
	 * @param request
	 * @return 1 : clusters , 0 : not clusters
	 */
	private boolean isClusterNodesChannelLogoutRequest(HttpServletRequest request) {
		String p = request.getParameter(this.isClusterNodesLogoutRequestParameterName);
		return "1".equals(p);
	}
	
	private void destroySessionFromClusterNodes(HttpServletRequest request) {
		String logoutMessage = CommonUtils.safeGetParameter(request, this.logoutParameterName, this.safeParameters);
		if (CommonUtils.isBlank(logoutMessage)) {
			logger.error("Could not locate logout message of the request from {}", this.logoutParameterName);
			return;
		}

		if (!logoutMessage.contains("SessionIndex")) {
			logoutMessage = uncompressLogoutMessage(logoutMessage);
		}

		logger.trace("ClusterNodes Logout request:\n{}", logoutMessage);
		if (CommonUtils.isNotBlank(logoutMessage)) {
			final String token = XmlUtils.getTextForElement(logoutMessage, "SessionIndex");
			if (CommonUtils.isNotBlank(token)) {
				final HttpSession session = this.sessionMappingStorage.removeSessionByMappingId(token);

				if (session != null) {
					final String sessionID = session.getId();
					logger.debug("ClusterNodes Invalidating session [{}] for token [{}]", sessionID, token);

					try {
						session.invalidate();
					} catch (final IllegalStateException e) {
						logger.debug("ClusterNodes Error invalidating session.", e);
					}
					this.logoutStrategy.logout(request);
				}
			}
		}
	}
	/*--------cluster client end--------*/
	
	/**
	 * Associates a token request with the current HTTP session by recording the
	 * mapping in the the configured {@link SessionMappingStorage} container.
	 * 
	 * @param request
	 *            HTTP request containing an authentication token.
	 */
	private void recordSession(final HttpServletRequest request) {
		final HttpSession session = request.getSession(this.eagerlyCreateSessions);

		if (session == null) {
			logger.debug(
					"No session currently exists (and none created).  Cannot record session information for single sign out.");
			return;
		}

		final String token = CommonUtils.safeGetParameter(request, this.artifactParameterName, this.safeParameters);
		logger.debug("Recording session for token {}", token);

		try {
			this.sessionMappingStorage.removeBySessionById(session.getId());
		} catch (final Exception e) {
			// ignore if the session is already marked as invalid. Nothing we can do!
		}
		sessionMappingStorage.addSessionById(token, session);
	}

	/**
	 * Uncompress a logout message (base64 + deflate).
	 * 
	 * @param originalMessage
	 *            the original logout message.
	 * @return the uncompressed logout message.
	 */
	private String uncompressLogoutMessage(final String originalMessage) {
		final byte[] binaryMessage = DatatypeConverter.parseBase64Binary(originalMessage);

		Inflater decompresser = null;
		try {
			// decompress the bytes
			decompresser = new Inflater();
			decompresser.setInput(binaryMessage);
			final byte[] result = new byte[binaryMessage.length * DECOMPRESSION_FACTOR];

			final int resultLength = decompresser.inflate(result);

			// decode the bytes into a String
			return new String(result, 0, resultLength, "UTF-8");
		} catch (final Exception e) {
			logger.error("Unable to decompress logout message", e);
			throw new RuntimeException(e);
		} finally {
			if (decompresser != null) {
				decompresser.end();
			}
		}
	}

	/**
	 * Destroys the current HTTP session for the given CAS logout request.
	 *
	 * @param request
	 *            HTTP request containing a CAS logout message.
	 */
	private void destroySession(final HttpServletRequest request) {
		String logoutMessage = CommonUtils.safeGetParameter(request, this.logoutParameterName, this.safeParameters);
		if (CommonUtils.isBlank(logoutMessage)) {
			logger.error("Could not locate logout message of the request from {}", this.logoutParameterName);
			return;
		}

		if (!logoutMessage.contains("SessionIndex")) {
			logoutMessage = uncompressLogoutMessage(logoutMessage);
		}

		logger.trace("Logout request:\n{}", logoutMessage);
		final String token = XmlUtils.getTextForElement(logoutMessage, "SessionIndex");
		if (CommonUtils.isNotBlank(token)) {
			final HttpSession session = this.sessionMappingStorage.removeSessionByMappingId(token);

			if (session != null) {
				final String sessionID = session.getId();
				logger.debug("Invalidating session [{}] for token [{}]", sessionID, token);

				try {
					session.invalidate();
				} catch (final IllegalStateException e) {
					logger.debug("Error invalidating session.", e);
				}
				this.logoutStrategy.logout(request);
			}
		}
		/*--------cluster client begin--------*/
		else {
			// detroy other clusters app's session
			destroySessionOfClusterNodes(token, request);
		}
		/*--------cluster client end--------*/
	}

	
	/*--------cluster client begin--------*/
	// private final ExecutorService pool = Executors.newFixedThreadPool(8);

	public static Set<String> clusters = null;
	public static String currentNode = null;

	/**
	 * destroy dession
	 * 
	 * @param request
	 */
	private void destroySessionOfClusterNodes(String token, HttpServletRequest request) {
		if (CollectionUtils.isEmpty(clusters)) {
			logger.warn("集群初始化失败!");
			return;
		}
		for (final String ip : clusters) {
			logger.debug("集群登出地址: {}", ip);
			if (ip.equals(currentNode)) {
				logger.debug("当前节点不执行clo");
				continue;
			}
			// // 三秒执行完，否则st会失效不可用
			// pool.execute(new Runnable() {
			// @Override
			// public void run() {
			try {
				mockPost("http://" + ip + "/login", token, request);
			} catch (Exception e) {
				logger.warn("clo post failed {}", e);
			}
			// }
			// });
		}
	}

	/**
	 * 执行带client的post请求
	 * 
	 * @param uri
	 * @param nameValuePairs
	 * @return
	 * @throws ClientProtocolException
	 * @throws IOException
	 * @throws HttpException
	 */
	private String mockPost(String uri, String token, HttpServletRequest request) {
		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair(this.isClusterNodesLogoutRequestParameterName, "1"));
		params.add(new BasicNameValuePair(this.artifactParameterName, token));
		Enumeration<String> parameterNames = request.getParameterNames();
		while (parameterNames.hasMoreElements()) {
			String paramName = parameterNames.nextElement();
			params.add(new BasicNameValuePair(paramName, request.getParameter(paramName)));
		}

		// 配置URI
		HttpPost post = new HttpPost(uri);
		int timeout = 3000; // 3秒
		post.setConfig(RequestConfig.custom().setConnectionRequestTimeout(timeout).setConnectTimeout(timeout)
				.setSocketTimeout(timeout).build());

		Enumeration<String> headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String headerName = headerNames.nextElement();
			post.setHeader(headerName, request.getHeader(headerName));
		}

		// 传参
		if (null != params && params.size() > 0) {
			UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params, Consts.UTF_8);
			post.setEntity(entity);
		}

		// 执行请求
		try {
			CloseableHttpClient client = this.createSSLClientDefault();
			CloseableHttpResponse response = client.execute(post);
			String result = returnStringRes(response);
			return result;
		} catch (Exception e) {
			logger.error("post uri {} ,param {} ,header {} \n{}", uri, JSONObject.toJSONString(params),
					JSONObject.toJSONString(headerNames), e);
			throw new RuntimeException(e);
		}
	}

	// 返回字符串
	private String returnStringRes(CloseableHttpResponse response) throws IOException, HttpResponseException {
		StatusLine statusLine = response.getStatusLine();
		String result = "";
		if (statusLine.getStatusCode() >= 200 && statusLine.getStatusCode() < 300) {
			// 获取返回实体
			HttpEntity responseEntity = response.getEntity();
			result = EntityUtils.toString(responseEntity, Consts.UTF_8);
			// 释放资源，关闭流
			EntityUtils.consume(responseEntity);
			response.close();
		} else {
			throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
		}
		return result;
	}

	/**
	 * 创建支持请求SSL服务的客户端
	 * 
	 * @return
	 */
	private CloseableHttpClient createSSLClientDefault() {
		// 允许所有ssl
		SSLContext sslContext;
		try {
			sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
				@Override
				public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType)
						throws java.security.cert.CertificateException {
					return true;
				}
			}).build();
		} catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException(e);
		}
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
		return HttpClients.custom().setSSLSocketFactory(sslsf).setMaxConnTotal(8).setMaxConnPerRoute(8)
				.setRetryHandler(new DefaultHttpRequestRetryHandler(1, true))
				.setDefaultConnectionConfig(ConnectionConfig.custom().setCharset(Charset.defaultCharset()).build())
				.build();
	}
	/*--------cluster client end--------*/
	
	private boolean isMultipartRequest(final HttpServletRequest request) {
		return request.getContentType() != null && request.getContentType().toLowerCase().startsWith("multipart");
	}

	private static boolean isServlet30() {
		try {
			return HttpServletRequest.class.getMethod("logout") != null;
		} catch (final NoSuchMethodException e) {
			return false;
		}
	}

	/**
	 * Abstracts the ways we can force logout with the Servlet spec.
	 */
	private interface LogoutStrategy {

		void logout(HttpServletRequest request);
	}

	private class Servlet25LogoutStrategy implements LogoutStrategy {

		public void logout(final HttpServletRequest request) {
			// nothing additional to do here
		}
	}

	private class Servlet30LogoutStrategy implements LogoutStrategy {

		public void logout(final HttpServletRequest request) {
			try {
				request.logout();
			} catch (final ServletException e) {
				logger.debug("Error performing request.logout.");
			}
		}
	}
}
