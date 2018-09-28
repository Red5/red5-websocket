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

import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.WriteRequestQueue;
import org.red5.net.websocket.model.WSMessage;
import org.red5.server.plugin.PluginRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketHandler
 * 
 * <pre>
 * IoHandlerAdapter for webSocket
 * </pre>
 * 
 * @author Toda Takahiko
 * @author Paul Gregoire
 */
public class WebSocketHandler extends IoHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(WebSocketHandler.class);

    /** {@inheritDoc} */
    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        if (log.isTraceEnabled()) {
            log.trace("Message received (session: {}) {}", session.getId(), message);
        }
        if (message instanceof WSMessage) {
            WebSocketConnection conn = (WebSocketConnection) session.getAttribute(Constants.CONNECTION);
            if (conn != null) {
                conn.receive((WSMessage) message);
            }
        } else {
            log.trace("Non-WSMessage received {}", message);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
        if (log.isTraceEnabled()) {
            log.trace("Message sent (session: {}) read: {} write: {}\n{}", session.getId(), session.getReadBytes(), session.getWrittenBytes(), String.valueOf(message));
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
        //if (log.isTraceEnabled()) {
        log.info("Idle (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
        //}
        int idleCount = 1;
        if (session.containsAttribute(Constants.IDLE_COUNTER)) {
            idleCount = (int) session.getAttribute(Constants.IDLE_COUNTER);
            idleCount += 1;
        } else {
            session.setAttribute(Constants.IDLE_COUNTER, idleCount);
        }
        // get the existing reference to a ws connection
        WebSocketConnection conn = (WebSocketConnection) session.getAttribute(Constants.CONNECTION);
        // after the first idle we force-close
        if (conn != null && idleCount == 1) {
            // close the idle socket
            conn.close();
        } else {
            log.info("Force closing idle session: {}", session);
            // clear write queue
            WriteRequestQueue writeQueue = session.getWriteRequestQueue();
            if (!writeQueue.isEmpty(session)) {
                writeQueue.clear(session);
            }
            // force close the session
            final CloseFuture future = session.closeNow();
            IoFutureListener<CloseFuture> listener = new IoFutureListener<CloseFuture>() {

                public void operationComplete(CloseFuture future) {
                    // now connection should be closed
                    log.info("Close operation completed {}: {}", session.getId(), future.isClosed());
                    future.removeListener(this);
                }

            };
            future.addListener(listener);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionClosed(IoSession session) throws Exception {
        log.trace("Session {} closed", session.getId());
        // remove connection from scope
        WebSocketConnection conn = (WebSocketConnection) session.removeAttribute(Constants.CONNECTION);
        if (conn != null) {
            // remove from the manager
            WebSocketPlugin plugin = (WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin");
            if (plugin != null) {
                String path = conn.getPath();
                if (path != null) {
                    WebSocketScopeManager manager = (WebSocketScopeManager) session.removeAttribute(Constants.MANAGER);
                    if (manager == null) {
                        manager = plugin.getManager(path);
                    }
                    if (manager != null) {
                        manager.removeConnection(conn);
                    } else {
                        log.debug("WebSocket manager was not found");
                    }
                } else {
                    log.debug("WebSocket connection path was null");
                }
            } else {
                log.debug("WebSocket plugin was not found");
            }
        } else {
            log.debug("WebSocket connection was null");
        }
        super.sessionClosed(session);
    }

    /** {@inheritDoc} */
    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        log.warn("Exception (session: {})", session.getId(), cause);
        // get the existing reference to a ws connection
        WebSocketConnection conn = (WebSocketConnection) session.getAttribute(Constants.CONNECTION);
        if (conn != null) {
            // close the socket
            conn.close();
        }
    }

}
