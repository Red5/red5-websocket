/*
 * RED5 Open Source Flash Server - http://code.google.com/p/red5/
 * 
 * Copyright 2006-2014 by respective authors (see below). All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.red5.net.websocket;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Map;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.red5.net.websocket.model.ConnectionType;
import org.red5.net.websocket.model.Packet;
import org.red5.net.websocket.util.IdGenerator;
import org.red5.server.plugin.PluginRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketConnection
 * <pre>
 * This class represents a WebSocket connection with a client (browser).
 * </pre>
 * 
 * @author Paul Gregoire
 */
public class WebSocketConnection {

	private static final Logger log = LoggerFactory.getLogger(WebSocketConnection.class);
	
	// session id
	private final long id = IdGenerator.generateId();

	// type of this connection; default is web / http
	private ConnectionType type = ConnectionType.WEB;

	private boolean connected;

	private IoSession session;

	private String host;

	private String path;

	private String origin;

	// secure or not
	private boolean secure;

	private Map<String, String> headers;
	
	/**
	 * constructor
	 */
	public WebSocketConnection(IoSession session) {
		this.session = session;
	}

	public ConnectionType getType() {
		return type;
	}

	public void setType(ConnectionType type) {
		this.type = type;
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
		return String.format("%s://%s%s", (secure ? "wss" : "ws"), host, path);
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

	public boolean isSecure() {
		return secure;
	}

	public void setSecure(boolean secure) {
		this.secure = secure;
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
		return id;
	}

	/**
	 * Returns true if this connection is a web-based connection.
	 * 
	 * @return true if web and false if direct
	 */
	public boolean isWebConnection() {
		return type == ConnectionType.WEB;
	}

	/**
	 * Sets the incoming headers.
	 * 
	 * @param headers
	 */
	public void setHeaders(Map<String, String> headers) {
		this.headers = headers;
	}

	public Map<String, String> getHeaders() {
		return headers;
	}

	/**
	 * receive data from a client.
	 * 
	 * @param message
	 */
	public void receive(IoBuffer message) {
		log.trace("receive message");
		if (isConnected()) {
			WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
			WebSocketScope scope = manager.getScope(getPath());
			scope.onMessage(message);
		} else {
			log.warn("Not connected");
		}
	}
	
	/**
	 * sendmessage to client
	 * @param data string data
	 * @throws UnsupportedEncodingException 
	 */
	public void send(String data) throws UnsupportedEncodingException {
		log.trace("send message: {}", data);
		send(data.getBytes());
	}

	/**
	 * sendmessage to client
	 * @param buffer IoBuffer data
	 */
	public void send(byte[] buf) {
		log.trace("send buffer: {}", Arrays.toString(buf));
		Packet packet = Packet.build(buf);
		session.write(packet);
	}

	/**
	 * close Connection
	 */
	public void close() {
		session.close(true);
	}

	@Override
	public String toString() {
		return "WebSocketConnection [id=" + id + ", type=" + type + ", host=" + host + ", origin=" + origin + ", path=" + path + ", secure=" + secure + ", connected=" + connected + "]";
	}

}
