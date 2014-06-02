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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.red5.net.websocket.listener.DefaultWebSocketDataListener;
import org.red5.net.websocket.listener.IWebSocketDataListener;
import org.red5.server.api.scope.IScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages websocket scopes and listeners.
 *
 * @author Toda Takahiko
 * @author Paul Gregoire
 */
public class WebSocketScopeManager {
	
	private static final Logger log = LoggerFactory.getLogger(WebSocketScopeManager.class);
	
	private Set<String> activeApplications = new HashSet<String>();

	private Map<String, WebSocketScope> scopes = new HashMap<String, WebSocketScope>();

	/**
	 * @return true:valid application name
	 */
	public boolean isEnabled(String application) {
		if (application.startsWith("/")) {
			int roomSlashPos = application.indexOf('/', 1);
			if (roomSlashPos == -1) {
				application = application.substring(1);
			} else {
				application = application.substring(1, roomSlashPos);
			}
		}
		log.debug("Enabled check on application: {}", application);
		return activeApplications.contains(application);
	}

	/**
	 * Adds an application level scope to the enabled applications.
	 * 
	 * @param scope the application scope
	 */
	public void addApplication(IScope scope) {
		String app = scope.getName();
		// add the name to the collection (no '/' prefix)
		activeApplications.add(app);
		// check the context for a predefined websocket scope
		if (scope.getContext().hasBean("webSocketScope")) {
			WebSocketScope wsScope = (WebSocketScope) scope.getContext().getBean("webSocketScope");
			// add to scopes
			scopes.put(String.format("/%s", app), wsScope);
		} else {
			// add a default scope and listener if none are defined
			WebSocketScope wsScope = new WebSocketScope();
			wsScope.setPath(String.format("/%s", app));
			wsScope.addListener(new DefaultWebSocketDataListener(scope));
			// add to scopes
			scopes.put(wsScope.getPath(), wsScope);
		}
	}

	/**
	 * Removes the application scope.
	 * 
	 * @param scope the application scope
	 */
	public void removeApplication(IScope scope) {
		activeApplications.remove(scope.getName());
	}

	/**
	 * add the connection on scope.
	 * @param conn WebSocketConnection
	 */
	public void addConnection(WebSocketConnection conn) {
		WebSocketScope scope = getScope(conn);
		scope.addConnection(conn);
	}

	/**
	 * remove connection from scope.
	 * @param conn WebSocketConnection
	 */
	public void removeConnection(WebSocketConnection conn) {
		WebSocketScope scope = getScope(conn);
		scope.removeConnection(conn);
		if (!scope.isValid()) {
			// scope is not valid. delete this.
			scopes.remove(scope);
		}
	}

	/**
	 * add the listener on scope
	 * @param listener IWebSocketDataListener
	 */
	public void addListener(IWebSocketDataListener listener) {
		WebSocketScope scope = getScope(listener);
		scope.addListener(listener);
	}

	/**
	 * remove listener from scope.
	 * @param listener IWebSocketDataListener
	 */
	public void removeListener(IWebSocketDataListener listener) {
		WebSocketScope scope = getScope(listener);
		scope.removeListener(listener);
		if (!scope.isValid()) {
			// scope is not valid. delete this.
			scopes.remove(scope);
		}
	}

	/**
	 * @param path scope path.
	 * @return scope instance.
	 */
	public WebSocketScope getScope(String path) {
		log.debug("getScope: {}", path);
		WebSocketScope scope = scopes.get(path);
		log.debug("Returning: {}", scope);
		return scope;
	}

	/**
	 * get corresponding scope, if no scope, make new one.
	 * @param conn 
	 * @return
	 */
	private WebSocketScope getScope(WebSocketConnection conn) {
		log.debug("getScope: {}", conn);
		WebSocketScope scope;
		String path = conn.getPath();
		if (!scopes.containsKey(path)) {
			scope = new WebSocketScope();
			scope.setPath(path);
			scopes.put(path, scope);
		} else {
			scope = scopes.get(path);
		}
		log.debug("Returning: {}", scope);
		return scope;
	}

	/**
	 * get corresponding scope, if no scope, make new one.
	 * @param listener 
	 * @return
	 */
	private WebSocketScope getScope(IWebSocketDataListener listener) {
		log.debug("getScope: {}", listener);
		WebSocketScope scope;
		String path = listener.getPath();
		if (!scopes.containsKey(path)) {
			scope = new WebSocketScope();
			scope.setPath(path);
			scopes.put(path, scope);
		} else {
			scope = scopes.get(path);
		}
		return scope;
	}
	
}
