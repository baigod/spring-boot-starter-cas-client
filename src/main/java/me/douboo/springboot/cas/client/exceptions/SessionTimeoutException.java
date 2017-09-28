package me.douboo.springboot.cas.client.exceptions;

public class SessionTimeoutException extends RuntimeException {

	private static final long serialVersionUID = -2099663546472519958L;

	public SessionTimeoutException() {
		super();
	}

	public SessionTimeoutException(String message, Throwable cause) {
		super(message, cause);
	}

	public SessionTimeoutException(String message) {
		super(message);
	}

	public SessionTimeoutException(Throwable cause) {
		super(cause);
	}

}
