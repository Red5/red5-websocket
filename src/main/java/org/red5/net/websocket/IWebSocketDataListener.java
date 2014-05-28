package org.red5.net.websocket;

import org.apache.mina.core.buffer.IoBuffer;

/**
 * Listener for execute packet data.
 */
public interface IWebSocketDataListener {
	
	/**
	 * @return path of the scope
	 */
	public String getPath();

	/**
	 * execute byte data.
	 * @param buf
	 */
	public void getData(IoBuffer buf);

	/**
	 * execute string data.
	 * @param message
	 */
	public void getMessage(String message);

	/**
	 * on connect new WebSocket client
	 * @param conn WebSocketConnection
	 */
	public void connect(WebSocketConnection conn);

	/**
	 * on leave WebSocket client
	 * @param conn WebSocketConnection
	 */
	public void leave(WebSocketConnection conn);
	
}
