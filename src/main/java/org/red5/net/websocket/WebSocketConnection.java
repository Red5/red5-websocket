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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.lang3.StringUtils;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;
import org.red5.net.websocket.model.ConnectionType;
import org.red5.net.websocket.model.HandshakeResponse;
import org.red5.net.websocket.model.MessageType;
import org.red5.net.websocket.model.Packet;
import org.red5.net.websocket.model.WSMessage;
import org.red5.net.websocket.util.IdGenerator;
import org.red5.server.plugin.PluginRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketConnection <br>
 * This class represents a WebSocket connection with a client (browser). <br>
 * {@link https://tools.ietf.org/html/rfc6455}
 * 
 * @author Paul Gregoire
 */
public class WebSocketConnection {

    private static final Logger log = LoggerFactory.getLogger(WebSocketConnection.class);

    // session id
    private final long id = IdGenerator.generateId();

    // type of this connection; default is web / http
    private ConnectionType type = ConnectionType.WEB;

    private AtomicBoolean connected = new AtomicBoolean(false);

    private CountDownLatch handshakeLatch = new CountDownLatch(1);

    private IoSession session;

    private String host;

    private String path;

    private String origin;

    // secure or not
    private boolean secure;

    /**
     * Contains http headers and other web-socket information from the initial request.
     */
    private Map<String, Object> headers;

    /**
     * Contains uri parameters from the initial request.
     */
    private Map<String, Object> querystringParameters;

    /**
     * Extensions enabled on this connection.
     */
    private Map<String, Object> extensions;

    /**
     * Connection protocol (ex. chat, json, etc)
     */
    private String protocol;

    /**
     * Policy enforcement.
     */
    private boolean sameOriginPolicy, crossOriginPolicy;

    /**
     * Allowed origins.
     */
    private List<String> allowedOrigins;

    /**
     * Timeout to wait for the handshake response to be written.
     */
    private long handshakeWriteTimeout;

    /**
     * Timeout to wait for handshake latch to be completed. Used to prevent sending to an socket that's not ready.
     */
    private long latchTimeout;
    
    /**
     * constructor
     */
    public WebSocketConnection(IoSession session) {
        this.session = session;
        // use initial configuration from WebSocketTransport
        sameOriginPolicy = WebSocketTransport.isSameOriginPolicy();
        crossOriginPolicy = WebSocketTransport.isCrossOriginPolicy();
        if (crossOriginPolicy) {
            allowedOrigins = new ArrayList<>();
            for (String origin : WebSocketTransport.getAllowedOrigins()) {
                allowedOrigins.add(origin);
            }
            log.debug("allowedOrigins: {}", allowedOrigins);
        }
        handshakeWriteTimeout = WebSocketTransport.getHandshakeWriteTimeout();
        latchTimeout = WebSocketTransport.getLatchTimeout();        
    }

    /**
     * Receive data from a client.
     * 
     * @param message
     */
    public void receive(WSMessage message) {
        log.trace("receive message");
        if (isConnected()) {
            WebSocketPlugin plugin = (WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin");
            Optional<WebSocketScopeManager> optional = Optional.ofNullable((WebSocketScopeManager) session.getAttribute(Constants.MANAGER));
            WebSocketScopeManager manager = optional.isPresent() ? optional.get() : plugin.getManager(path);
            WebSocketScope scope = manager.getScope(path);
            scope.onMessage(message);
        } else {
            log.warn("Not connected");
        }
    }

    /**
     * Sends the handshake response.
     * 
     * @param wsResponse
     */
    public void sendHandshakeResponse(HandshakeResponse wsResponse) {
        // we'll do this in a separate thread so it wont violate the mina io rules
        Thread hs = new Thread(new Runnable() {

            @Override
            public void run() {
                // create write future
                WriteFuture future = session.write(wsResponse);
                future.addListener(new IoFutureListener<WriteFuture>() {

                    @Override
                    public void operationComplete(WriteFuture future) {
                        if (future.isWritten()) {
                            // handshake is finished
                            log.debug("Handshake write success!");
                            session.setAttribute(Constants.HANDSHAKE_COMPLETE);
                            setConnected();
                        } else {
                            log.debug("Handshake write failed from: {} to: {}", future.getSession().getLocalAddress(), future.getSession().getRemoteAddress());
                        }
                        handshakeLatch.countDown();
                    }

                });
                if (future.awaitUninterruptibly(handshakeWriteTimeout, TimeUnit.MILLISECONDS)) {
                    log.debug("Handshake write completed within {}ms", handshakeWriteTimeout);
                } else {
                    log.debug("Handshake write did not completed within {}ms", handshakeWriteTimeout);
                }
                log.debug("Handshake complete: {}", session.containsAttribute(Constants.HANDSHAKE_COMPLETE));
            }
        }, String.format("WSHandshakeResponse@%d", session.getId()));
        hs.setDaemon(true);
        hs.start();
    }

    /**
     * Sends text to the client.
     * 
     * @param data
     *            string data
     * @throws UnsupportedEncodingException
     */
    public void send(String data) throws UnsupportedEncodingException {
        log.trace("send message: {}", data);
        try {
            if (handshakeLatch.await(latchTimeout, TimeUnit.MILLISECONDS)) {
                if (StringUtils.isNotBlank(data)) {
                    Packet packet = Packet.build(data.getBytes("UTF8"), MessageType.TEXT);
                    session.write(packet);
                } else {
                    throw new UnsupportedEncodingException("Cannot send a null string");
                }
            } else {
                log.warn("Timed out waiting for handshake to complete, send failed");
            }
        } catch (InterruptedException e) {
            log.warn("Interrupted waiting for handshake to complete, send failed", e);
        }
    }

    /**
     * Sends binary data to the client.
     * 
     * @param buf
     */
    public void send(byte[] buf) {
        if (log.isTraceEnabled()) {
            log.trace("send binary: {}", Arrays.toString(buf));
        }
        try {
            if (handshakeLatch.await(latchTimeout, TimeUnit.MILLISECONDS)) {
                Packet packet = Packet.build(buf);
                session.write(packet);
            } else {
                log.warn("Timed out waiting for handshake to complete, send failed");
            }
        } catch (InterruptedException e) {
            log.warn("Interrupted waiting for handshake to complete, send failed", e);
        }
    }

    /**
     * Sends a pong back to the client; normally in response to a ping.
     * 
     * @param buf
     */
    public void sendPong(byte[] buf) {
        if (log.isTraceEnabled()) {
            log.trace("send pong: {}", buf);
        }
        Packet packet = Packet.build(buf, MessageType.PONG);
        session.write(packet);
    }

    /**
     * close Connection
     */
    public void close() {
        if (connected.compareAndSet(true, false)) {
            // send a proper ws close
            Packet packet = Packet.build(Constants.CLOSE_MESSAGE_BYTES, MessageType.CLOSE);
            WriteFuture writeFuture = session.write(packet);
            writeFuture.addListener(new IoFutureListener<WriteFuture>() {

                @Override
                public void operationComplete(WriteFuture future) {
                    if (future.isWritten()) {
                        log.debug("Close message written");
                        // only set on success for now to skip boolean check later
                        session.setAttribute(Constants.STATUS_CLOSE_WRITTEN, Boolean.TRUE);
                    }
                    future.removeListener(this);
                }

            });
            // adjust close routine to allow for flushing
            CloseFuture closeFuture = session.closeOnFlush();
            closeFuture.addListener(new IoFutureListener<CloseFuture>() {

                public void operationComplete(CloseFuture future) {
                    if (future.isClosed()) {
                        log.debug("Connection is closed");
                    } else {
                        log.debug("Connection is not yet closed");
                    }
                    future.removeListener(this);
                }

            });
        }
    }

    /**
     * Close with an associated error status.
     * 
     * @param statusCode
     * @param errResponse
     */
    public void close(int statusCode, HandshakeResponse errResponse) {
        log.warn("Closing connection with status: {}", statusCode);
        // send http error response
        session.write(errResponse);
        // now send close packet with error code
        IoBuffer buf = IoBuffer.allocate(16);
        buf.setAutoExpand(true);
        // all errors except 403 will use 1002
        buf.putUnsigned((short) statusCode);
        try {
            if (statusCode == 1008) {
                // if its a 403 forbidden
                buf.put("Policy Violation".getBytes("UTF8"));
            } else {
                buf.put("Protocol error".getBytes("UTF8"));
            }
        } catch (Exception e) {
            // shouldnt be any text encoding issues...
        }
        buf.flip();
        byte[] errBytes = new byte[buf.remaining()];
        buf.get(errBytes);
        // construct the packet
        Packet packet = Packet.build(errBytes, MessageType.CLOSE);
        WriteFuture writeFuture = session.write(packet);
        writeFuture.addListener(new IoFutureListener<WriteFuture>() {

            @Override
            public void operationComplete(WriteFuture future) {
                if (future.isWritten()) {
                    log.debug("Close message written");
                    // only set on success for now to skip boolean check later
                    session.setAttribute(Constants.STATUS_CLOSE_WRITTEN, Boolean.TRUE);
                }
                future.removeListener(this);
            }

        });
        // adjust close routine to allow for flushing
        CloseFuture closeFuture = session.closeOnFlush();
        closeFuture.addListener(new IoFutureListener<CloseFuture>() {

            public void operationComplete(CloseFuture future) {
                if (future.isClosed()) {
                    log.debug("Connection is closed");
                } else {
                    log.debug("Connection is not yet closed");
                }
                future.removeListener(this);
            }

        });
        log.debug("Close complete");
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
        return connected.get();
    }

    /**
     * on connected, put flg and clear keys.
     */
    public void setConnected() {
        connected.compareAndSet(false, true);
    }

    /**
     * @return the host
     */
    public String getHost() {
        return String.format("%s://%s%s", (secure ? "wss" : "ws"), host, path);
    }

    /**
     * @param host
     *            the host to set
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
     * @param origin
     *            the origin to set
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
     * @param path
     *            the path to set
     */
    public void setPath(String path) {
        if (path.charAt(path.length() - 1) == '/') {
            this.path = path.substring(0, path.length() - 1);
        } else {
            this.path = path;
        }
    }

    /**
     * Returns the connection id.
     * 
     * @return id
     */
    public long getId() {
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
    public void setHeaders(Map<String, Object> headers) {
        this.headers = headers;
    }

    public Map<String, Object> getHeaders() {
        return headers;
    }

    public Map<String, Object> getQuerystringParameters() {
        return querystringParameters;
    }

    public void setQuerystringParameters(Map<String, Object> querystringParameters) {
        this.querystringParameters = querystringParameters;
    }

    /**
     * Returns whether or not extensions are enabled on this connection.
     * 
     * @return true if extensions are enabled, false otherwise
     */
    public boolean hasExtensions() {
        return extensions != null && !extensions.isEmpty();
    }

    /**
     * Returns enabled extensions.
     * 
     * @return extensions
     */
    public Map<String, Object> getExtensions() {
        return extensions;
    }

    /**
     * Sets the extensions.
     * 
     * @param extensions
     */
    public void setExtensions(Map<String, Object> extensions) {
        this.extensions = extensions;
    }

    /**
     * Returns the extensions list as a comma separated string as specified by the rfc.
     * 
     * @return extension list string or null if no extensions are enabled
     */
    public String getExtensionsAsString() {
        String extensionsList = null;
        if (extensions != null) {
            StringBuilder sb = new StringBuilder();
            for (String key : extensions.keySet()) {
                sb.append(key);
                sb.append("; ");
            }
            extensionsList = sb.toString().trim();
        }
        return extensionsList;
    }

    /**
     * Returns whether or not a protocol is enabled on this connection.
     * 
     * @return true if protocol is enabled, false otherwise
     */
    public boolean hasProtocol() {
        return protocol != null;
    }

    /**
     * Returns the protocol enabled on this connection.
     * 
     * @return protocol
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * Sets the protocol.
     * 
     * @param protocol
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public long getHandshakeWriteTimeout() {
        return handshakeWriteTimeout;
    }

    public void setHandshakeWriteTimeout(long handshakeWriteTimeout) {
        this.handshakeWriteTimeout = handshakeWriteTimeout;
    }

    public long getLatchTimeout() {
        return latchTimeout;
    }

    public void setLatchTimeout(long latchTimeout) {
        this.latchTimeout = latchTimeout;
    }

    public boolean isSameOriginPolicy() {
        return sameOriginPolicy;
    }

    public boolean isCrossOriginPolicy() {
        return crossOriginPolicy;
    }

    public void addOrigin(String origin) {
        if (allowedOrigins == null) {
            allowedOrigins = new ArrayList<>();
        }
        allowedOrigins.add(origin);
    }

    public boolean removeOrigin(String origin) {
        return allowedOrigins.remove(origin);
    }

    public void clearOrigins() {
        allowedOrigins.clear();
    }

    public boolean isValidOrigin(String origin) {
        if (allowedOrigins != null) {
            // short-cut
            if (allowedOrigins.contains("*")) {
                return true;
            }
            return allowedOrigins.contains(origin);
        }
        return true;
    }

    @Override
    public String toString() {
        return "WebSocketConnection [id=" + id + ", type=" + type + ", host=" + host + ", origin=" + origin + ", path=" + path + ", secure=" + secure + ", connected=" + connected + ", remote=" + (session != null ? session.getRemoteAddress().toString() : "unk") + "]";
    }

}
