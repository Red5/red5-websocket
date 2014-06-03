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

import java.util.HashSet;
import java.util.Set;

import org.red5.net.websocket.listener.IWebSocketDataListener;
import org.red5.net.websocket.model.WSMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebSocketScope {

	private static final Logger log = LoggerFactory.getLogger(WebSocketScope.class);
	
	private String path;

	private Set<WebSocketConnection> conns = new HashSet<WebSocketConnection>();

	private Set<IWebSocketDataListener> listeners = new HashSet<IWebSocketDataListener>();

	/**
	 * get the set of connections
	 * @return the conns
	 */
	public Set<WebSocketConnection> getConns() {
		return conns;
	}

	public void setPath(String path) {
		this.path = path; // /room/name
	}

	/**
	 * get the path info of scope
	 * @return path data.
	 */
	public String getPath() {
		return path;
	}

	/**
	 * add new connection on scope
	 * @param conn WebSocketConnection
	 */
	public void addConnection(WebSocketConnection conn) {
		conns.add(conn);
		for (IWebSocketDataListener listener : listeners) {
			listener.onWSConnect(conn);
		}
	}

	/**
	 * remove connection from scope
	 * @param conn WebSocketConnection
	 */
	public void removeConnection(WebSocketConnection conn) {
		conns.remove(conn);
		for (IWebSocketDataListener listener : listeners) {
			listener.onWSDisconnect(conn);
		}
	}

	/**
	 * add new listener on scope
	 * @param listener IWebSocketDataListener
	 */
	public void addListener(IWebSocketDataListener listener) {
		log.info("addListener: {}", listener.getPath());
		listeners.add(listener);
	}

	/**
	 * remove listener from scope
	 * @param listener IWebSocketDataListener
	 */
	public void removeListener(IWebSocketDataListener listener) {
		log.info("removeListener: {}", listener.getPath());
		listeners.remove(listener);
	}

	/**
	 * Check the scope state.
	 * 
	 * @return true:still have relation
	 */
	public boolean isValid() {
		return (conns.size() + listeners.size()) > 0;
	}

	/**
	 * Message received from client
	 * 
	 * @param message
	 */
	public void onMessage(WSMessage message) {
		log.trace("Listeners: {}", listeners.size());
		for (IWebSocketDataListener listener : listeners) {
			try {
				listener.onWSMessage(message);
			} catch (Exception e) {
				log.warn("onMessage exception", e);
			}
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((path == null) ? 0 : path.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		WebSocketScope other = (WebSocketScope) obj;
		if (path == null) {
			if (other.path != null)
				return false;
		} else if (!path.equals(other.path))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "WebSocketScope [path=" + path + "]";
	}
	
}
