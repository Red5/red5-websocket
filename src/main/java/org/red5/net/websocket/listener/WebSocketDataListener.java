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

package org.red5.net.websocket.listener;

import org.red5.server.api.scope.IScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter class for WebSocket data listener.
 * 
 * @author Toda Takahiko
 */
public abstract class WebSocketDataListener implements IWebSocketDataListener {
	
	private static final Logger log = LoggerFactory.getLogger(WebSocketDataListener.class);
	
	protected String fullPath;
	
	protected String path;

	/**
	 * constructor with scope input.
	 * <pre>
	 * to make default path.
	 * </pre>
	 */
	public WebSocketDataListener(IScope scope) {
		fullPath = String.format("%s/%s", scope.getPath(), scope.getName());
		log.debug("WebSocketDataListener: {}", fullPath);
		this.path = String.format("/%s", scope.getName());
		log.debug("Path: {}", path);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getPath() {
		return path;
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
		WebSocketDataListener other = (WebSocketDataListener) obj;
		if (path == null) {
			if (other.path != null)
				return false;
		} else if (!path.equals(other.path))
			return false;
		return true;
	}
	
}
