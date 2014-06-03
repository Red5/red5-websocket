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

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.red5.net.websocket.model.WSMessage;
import org.red5.server.plugin.PluginRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketHandler
 * <pre>
 * IoHandlerAdapter for webSocket
 * </pre>
 * @author Toda Takahiko
 * @author Paul Gregoire
 */
public class WebSocketHandler extends IoHandlerAdapter {

	private static final Logger log = LoggerFactory.getLogger(WebSocketHandler.class);
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void messageReceived(IoSession session, Object message) throws Exception {
		log.trace("Message received on session: {}", session.getId());
		if (message instanceof WSMessage) {
			WebSocketConnection conn = (WebSocketConnection) session.getAttribute("connection");
			if (conn != null) {
				conn.receive((WSMessage) message);
			}
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
    public void messageSent(IoSession session, Object message) throws Exception {
		log.trace("Message sent on session: {}", session.getId());
    	
    }
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void sessionClosed(IoSession session) throws Exception {
		log.trace("Session closed");
		// remove connection from scope
		WebSocketConnection conn = (WebSocketConnection) session.getAttribute("connection");
		// remove from the manager
		WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
		manager.removeConnection(conn);
		super.sessionClosed(session);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
		log.error("exception", cause);
	}	
	
}
