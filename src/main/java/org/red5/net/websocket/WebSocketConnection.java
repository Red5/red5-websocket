package org.red5.net.websocket;

import java.io.UnsupportedEncodingException;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;

import org.red5.server.plugin.PluginRegistry;

/**
 * WebSocketConnection
 * <pre>
 * data for connection.
 * </pre>
 */
public class WebSocketConnection {

	private boolean connected;

	private IoSession session;

	private String host;

	private String path;

	private String origin;

	/**
	 * constructor
	 */
	public WebSocketConnection(IoSession session) {
		this.session = session;
	}

	/**
	 * @return the connected
	 */
	public boolean isConnected() {
		return connected;
	}

	/**
	 * on connected, put flg and clear keys.
	 */
	public void setConnected() {
		connected = true;
	}

	/**
	 * @return the host
	 */
	public String getHost() {
		return String.format("ws://%s%s", host, path);
	}

	/**
	 * @param host the host to set
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * @return the origin
	 */
	public String getOrigin() {
		return origin;
	}

	/**
	 * @param origin the origin to set
	 */
	public void setOrigin(String origin) {
		this.origin = origin;
	}

	/**
	 * @return the session
	 */
	public IoSession getSession() {
		return session;
	}

	public String getPath() {
		return path;
	}

	/**
	 * @param path the path to set
	 */
	public void setPath(String path) {
		if (path.charAt(path.length() - 1) == '/') {
			this.path = path.substring(0, path.length() - 1);
		} else {
			this.path = path;
		}
	}

	/**
	 * get the connection id
	 * @return id
	 * @throws WebSocketException when the session is invalid...
	 */
	public long getId() throws WebSocketException {
		if (session == null) {
			throw new WebSocketException("invalid connection");
		}
		return session.getId();
	}

	/**
	 * sendmessage to client
	 * @param buffer IoBuffer data
	 */
	public void send(IoBuffer buffer) {
		session.write(buffer);
	}

	/**
	 * sendmessage to client
	 * @param data string data
	 * @throws UnsupportedEncodingException 
	 */
	public void send(String data) throws UnsupportedEncodingException {
		IoBuffer buffer = IoBuffer.allocate(data.getBytes("UTF8").length + 4);
		buffer.put((byte) 0x00);
		buffer.put(data.getBytes("UTF8"));
		buffer.put((byte) 0xFF);
		buffer.flip();
		session.write(buffer);
	}

	/**
	 * receive message
	 * @param buffer
	 */
	public void receive(IoBuffer buffer) {
		if (isConnected()) {
			WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
			WebSocketScope scope = manager.getScope(getPath());
			scope.setMessage(buffer);
		} else {
			WebSocketHandshake handshake = new WebSocketHandshake(this);
			try {
				handshake.handShake(buffer);
			} catch (WebSocketException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * close Connection
	 */
	public void close() {
		WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
		manager.removeConnection(this);
		session.close(true);
	}
}
