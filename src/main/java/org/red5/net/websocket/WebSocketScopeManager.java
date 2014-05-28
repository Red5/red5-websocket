package org.red5.net.websocket;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * to manage scopes.
 * @author Toda Takahiko
 */
public class WebSocketScopeManager {
	
	private static Set<String> pluginedApplicationSet = new HashSet<String>();

	private static Map<String, WebSocketScope> scopes = new HashMap<String, WebSocketScope>();

	/**
	 * @return true:valid application name,
	 */
	public boolean isPluginedApplication(String application) {
		return pluginedApplicationSet.contains(application);
	}

	/**
	 * @param application application name.
	 */
	public void addPluginedApplication(String application) {
		pluginedApplicationSet.add(application);
	}

	/**
	 * @param path scope path.
	 * @return scope instance.
	 */
	public WebSocketScope getScope(String path) {
		return scopes.get(path);
	}

	/**
	 * add the connection on scope.
	 * @param conn WebSocketConnection
	 */
	public void addConnection(WebSocketConnection conn) {
		WebSocketScope scope;
		scope = getScope(conn);
		scope.addConnection(conn);
	}

	/**
	 * remove connection from scope.
	 * @param conn WebSocketConnection
	 */
	public void removeConnection(WebSocketConnection conn) {
		WebSocketScope scope;
		scope = getScope(conn);
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
		WebSocketScope scope;
		scope = getScope(listener);
		scope.addListener(listener);
	}

	/**
	 * remove listener from scope.
	 * @param listener IWebSocketDataListener
	 */
	public void removeListener(IWebSocketDataListener listener) {
		WebSocketScope scope;
		scope = getScope(listener);
		scope.removeListener(listener);
		if (!scope.isValid()) {
			// scope is not valid. delete this.
			scopes.remove(scope);
		}
	}

	/**
	 * get corresponding scope, if no scope, make new one.
	 * @param conn 
	 * @return
	 */
	private WebSocketScope getScope(WebSocketConnection conn) {
		WebSocketScope scope;
		if (!scopes.containsKey(conn.getPath())) {
			scope = new WebSocketScope(conn.getPath());
			scopes.put(conn.getPath(), scope);
		} else {
			scope = scopes.get(conn.getPath());
		}
		return scope;
	}

	/**
	 * get corresponding scope, if no scope, make new one.
	 * @param listener 
	 * @return
	 */
	private WebSocketScope getScope(IWebSocketDataListener listener) {
		WebSocketScope scope;
		if (!scopes.containsKey(listener.getPath())) {
			scope = new WebSocketScope(listener.getPath());
			scopes.put(listener.getPath(), scope);
		} else {
			scope = scopes.get(listener.getPath());
		}
		return scope;
	}
}
