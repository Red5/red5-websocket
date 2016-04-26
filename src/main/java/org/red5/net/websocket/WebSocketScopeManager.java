/*
 * RED5 Open Source Flash Server - https://github.com/red5
 * 
 * Copyright 2006-2015 by respective authors (see below). All rights reserved.
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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.red5.net.websocket.listener.DefaultWebSocketDataListener;
import org.red5.net.websocket.listener.IWebSocketDataListener;
import org.red5.net.websocket.listener.IWebSocketScopeListener;
import org.red5.server.api.IContext;
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

    private CopyOnWriteArraySet<String> activeApplications = new CopyOnWriteArraySet<>();

    private static CopyOnWriteArraySet<IWebSocketScopeListener> scopeListners = new CopyOnWriteArraySet<>();

    private ConcurrentMap<String, WebSocketScope> scopes = new ConcurrentHashMap<>();

    public static void addListener(IWebSocketScopeListener listner) {
        scopeListners.add(listner);
    }

    public static void removeListener(IWebSocketScopeListener listner) {
        scopeListners.remove(listner);
    }

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
        boolean enabled = activeApplications.contains(application);
        log.debug("Enabled check on application: {} enabled: {}", application, enabled);
        return enabled;
    }

    /**
     * Adds an application level scope to the enabled applications.
     * 
     * @param scope
     *            the application scope
     */
    public void addApplication(IScope scope) {
        String app = scope.getName();
        // add the name to the collection (no '/' prefix)
        activeApplications.add(app);
        // check the context for a predefined websocket scope
        IContext ctx = scope.getContext();
        if (ctx != null && ctx.hasBean("webSocketScopeDefault")) {
            log.debug("WebSocket scope found in context");
            WebSocketScope wsScope = (WebSocketScope) scope.getContext().getBean("webSocketScopeDefault");
            if (wsScope != null) {
                log.trace("Default WebSocketScope has {} listeners", wsScope.getListeners().size());
            }
            // add to scopes
            scopes.put(String.format("/%s", app), wsScope);
        } else {
            log.debug("Creating a new scope");
            // add a default scope and listener if none are defined
            WebSocketScope wsScope = new WebSocketScope();
            wsScope.setScope(scope); 
            wsScope.setPath(String.format("/%s", app));
            // add to scopes
            scopes.put(wsScope.getPath(), wsScope);
            notifyListeners(wsScope);
            if (wsScope.getListeners().isEmpty()) {
                log.debug("adding default listener");
                wsScope.addListener(new DefaultWebSocketDataListener());
            }
        }
    }

    private static void notifyListeners(WebSocketScope wsScope) {
        for (IWebSocketScopeListener l : scopeListners) {
            l.scopeCreated(wsScope);
        }
    }

    /**
     * Removes the application scope.
     * 
     * @param scope
     *            the application scope
     */
    public void removeApplication(IScope scope) {
        activeApplications.remove(scope.getName());
    }

    /**
     * Adds a websocket scope.
     * 
     * @param webSocketScope
     */
    public void addWebSocketScope(WebSocketScope webSocketScope) {
        String path = webSocketScope.getPath();
        if (!scopes.containsKey(path)) {
            scopes.put(path, webSocketScope);
            log.info("addWebSocketScope: {}", webSocketScope);
        }
    }

    /**
     * Removes a websocket scope.
     * 
     * @param webSocketScope
     */
    public void removeWebSocketScope(WebSocketScope webSocketScope) {
        log.info("removeWebSocketScope: {}", webSocketScope);
        scopes.remove(webSocketScope.getPath());
    }

    /**
     * Add the connection on scope.
     * 
     * @param conn
     *            WebSocketConnection
     */
    public void addConnection(WebSocketConnection conn) {
        WebSocketScope scope = getScope(conn);
        scope.addConnection(conn);
    }

    /**
     * Remove connection from scope.
     * 
     * @param conn
     *            WebSocketConnection
     */
    public void removeConnection(WebSocketConnection conn) {
        if (conn != null) {
            WebSocketScope scope = getScope(conn);
            if (scope != null) {
                scope.removeConnection(conn);
                if (!scope.isValid()) {
                    // scope is not valid. delete this.
                    scopes.remove(scope);
                }
            }
        }
    }

    /**
     * Add the listener on scope via its path.
     * 
     * @param listener
     *            IWebSocketDataListener
     * @param path
     */
    public void addListener(IWebSocketDataListener listener, String path) {
        log.trace("addListener: {}", listener);
        WebSocketScope scope = getScope(path);
        if (scope != null) {
            scope.addListener(listener);
        } else {
            log.info("Scope not found for path: {}", path);
        }
    }

    /**
     * Remove listener from scope via its path.
     * 
     * @param listener
     *            IWebSocketDataListener
     * @param path
     */
    public void removeListener(IWebSocketDataListener listener, String path) {
        log.trace("removeListener: {}", listener);
        WebSocketScope scope = getScope(path);
        if (scope != null) {
            scope.removeListener(listener);
            if (!scope.isValid()) {
                // scope is not valid. delete this
                scopes.remove(scope);
            }
        } else {
            log.info("Scope not found for path: {}", path);
        }
    }

    /**
     * Get the corresponding scope.
     * 
     * @param path
     *            scope path
     * @return scope
     */
    public WebSocketScope getScope(String path) {
        log.debug("getScope: {}", path);
        WebSocketScope scope = scopes.get(path);
        // if we dont find a scope, go for default
        if (scope == null) {
            scope = scopes.get("default");
        }
        log.debug("Returning: {}", scope);
        return scope;
    }

    /**
     * Create a web socket scope. Use the IWebSocketScopeListener interface to configure the created scope.
     * @param path
     */
    public void makeScope(String path) {
        log.debug("makeScope: {}", path);
        WebSocketScope scope=null;
        if (!scopes.containsKey(path)) {
            scope = new WebSocketScope();
            scope.setPath(path);
            scopes.put(path, scope);
            notifyListeners(scope);
            log.debug("Use the IWebSocketScopeListener interface to be notified of new scopes");
        } else {
            log.debug("Scope already exists: {}", path);
        }
    }

    /**
     * Get the corresponding scope, if none exists, make new one.
     * 
     * @param conn
     * @return scope
     */
    private WebSocketScope getScope(WebSocketConnection conn) {
        if (log.isTraceEnabled()) {
            log.trace("Scopes: {}", scopes);
        }
        log.debug("getScope: {}", conn);
        WebSocketScope scope;
        String path = conn.getPath();
        if (!scopes.containsKey(path)) {
            // check for default scope
            if (!scopes.containsKey("default")) {
                scope = new WebSocketScope();
                scope.setPath(path);
                scopes.put(path, scope);
                notifyListeners(scope);
                log.debug("Use the IWebSocketScopeListener interface to be notified of new scopes");
            } else {
                path = "default";
            }
        }
        scope = scopes.get(path);
        log.debug("Returning: {}", scope);
        return scope;
    }

}
