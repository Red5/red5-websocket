package org.red5.net.websocket.codec.extension;

/**
 * Common interface for WebSocket extensions.
 * 
 * @author Paul Gregoire
 */
public interface WebSocketExtension {

	/**
	 * Returns the extensions identifying string.
	 * 
	 * @return id
	 */
	String getId();

}
