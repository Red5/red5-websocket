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

import org.red5.server.Server;
import org.red5.server.adapter.MultiThreadedApplicationAdapter;
import org.red5.server.plugin.Red5Plugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketPlugin
 * <pre>
 * This program will be called by red5 PluginLauncher
 * and hold the application Context or Application Adapter
 * </pre>
 * @author Toda Takahiko
 * @author Paul Gregoire
 */
public class WebSocketPlugin extends Red5Plugin {

	private Logger log = LoggerFactory.getLogger(WebSocketPlugin.class);

	private WebSocketScopeManager manager = new WebSocketScopeManager();

	public WebSocketPlugin() {
		log.info("WebSocketPlugin ctor");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doStart() throws Exception {
		super.doStart();
		log.info("WebSocketPlugin start");
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

	public WebSocketScopeManager getManager() {
		return manager;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setApplication(MultiThreadedApplicationAdapter application) {
		log.info("WebSocketPlugin application: {}", application);
		manager.addApplication(application.getScope());
		super.setApplication(application);
	}
	
}
