package org.red5.net.websocket;

import org.red5.server.api.scope.IScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author Toda Takahiko
 */
public abstract class WebSocketAbstractDataListener implements IWebSocketDataListener {
	
	private static final Logger log = LoggerFactory.getLogger(WebSocketAbstractDataListener.class);
	
	protected String path;

	/**
	 * constructor with scope input.
	 * <pre>
	 * to make default path.
	 * </pre>
	 */
	public WebSocketAbstractDataListener(IScope scope) {
		String path = String.format("%s/%s", scope.getPath(), scope.getName());
		log.debug("WebSocketAbstractData: {}", path);
		this.path = path.split("/default")[1];
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getPath() {
		return path;
	}
}
