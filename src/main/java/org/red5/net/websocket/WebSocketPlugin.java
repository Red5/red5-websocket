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

import java.util.Arrays;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.red5.server.Server;
import org.red5.server.adapter.MultiThreadedApplicationAdapter;
import org.red5.server.api.scope.IScope;
import org.red5.server.plugin.Red5Plugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketPlugin
 * 
 * <pre>
 * This program will be called by red5 PluginLauncher
 * and hold the application Context or Application Adapter
 * </pre>
 * 
 * @author Toda Takahiko
 * @author Paul Gregoire
 */
public class WebSocketPlugin extends Red5Plugin {

    private Logger log = LoggerFactory.getLogger(WebSocketPlugin.class);

    // holds application scopes and their associated websocket scope manager
    private static ConcurrentMap<IScope, WebSocketScopeManager> managerMap = new ConcurrentHashMap<>();

    public WebSocketPlugin() {
        log.trace("WebSocketPlugin ctor");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doStart() throws Exception {
        super.doStart();
        log.trace("WebSocketPlugin start");
    }

    @Override
    public void doStop() throws Exception {
        if (!managerMap.isEmpty()) {
            for (Entry<IScope, WebSocketScopeManager> entry : managerMap.entrySet()) {
                entry.getValue().stop();
            }
            managerMap.clear();
        }
        super.doStop();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return "WebSocketPlugin";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Server getServer() {
        return super.getServer();
    }

    /**
     * Returns a WebSocketScopeManager for a given scope.
     * 
     * @param scope
     * @return WebSocketScopeManager if registered for the given scope and null otherwise
     */
    public WebSocketScopeManager getManager(IScope scope) {
        return managerMap.get(scope);
    }

    /**
     * Returns a WebSocketScopeManager for a given path.
     * 
     * @param path
     * @return WebSocketScopeManager if registered for the given path and null otherwise
     */
    public WebSocketScopeManager getManager(String path) {
        log.debug("getManager: {}", path);
        // determine what the app scope name is
        String[] parts = path.split("\\/");
        if (log.isTraceEnabled()) {
            log.trace("Path parts: {}", Arrays.toString(parts));
        }
        if (parts.length > 0) {
            for (Entry<IScope, WebSocketScopeManager> entry : managerMap.entrySet()) {
                IScope appScope = entry.getKey();
                if (appScope.getName().equals(parts[1])) {
                    log.debug("Application scope name matches path: {}", parts[1]);
                    return entry.getValue();
                } else if (log.isTraceEnabled()) {
                    log.trace("Application scope name: {} didnt match path: {}", appScope.getName(), parts[1]);
                }
            }
        }
        return null;
    }

    @Deprecated
    public WebSocketScopeManager getManager() {
        throw new UnsupportedOperationException("Use getManager(IScope scope) instead");
    }

    /**
     * Removes and returns the WebSocketScopeManager for the given scope if it exists and returns null if it does not.
     *
     * @param scope Scope for which the manager is registered
     * @return WebSocketScopeManager if registered for the given path and null otherwise
     */
    public WebSocketScopeManager removeManager(IScope scope) {
        return managerMap.remove(scope);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setApplication(MultiThreadedApplicationAdapter application) {
        log.info("WebSocketPlugin application: {}", application);
        // get the app scope
        IScope appScope = application.getScope();
        // put if not already there
        managerMap.putIfAbsent(appScope, new WebSocketScopeManager());
        // add the app scope to the manager
        managerMap.get(appScope).setApplication(appScope);
        super.setApplication(application);
    }

}
