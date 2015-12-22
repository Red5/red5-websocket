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
import java.util.Arrays;
import java.util.Map;

import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.session.IoSession;
import org.red5.net.websocket.model.ConnectionType;
import org.red5.net.websocket.model.MessageType;
import org.red5.net.websocket.model.Packet;
import org.red5.net.websocket.model.WSMessage;
import org.red5.net.websocket.util.IdGenerator;
import org.red5.server.plugin.PluginRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketConnection
 * 
 * <pre>
 * This class represents a WebSocket connection with a client (browser).
 * </pre>
 * 
 * @author Paul Gregoire
 */
public class WebSocketConnection {

    private static final Logger log = LoggerFactory.getLogger(WebSocketConnection.class);

    // session id
    private final long id = IdGenerator.generateId();

    // type of this connection; default is web / http
    private ConnectionType type = ConnectionType.WEB;

    private boolean connected;

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
     * constructor
     */
    public WebSocketConnection(IoSession session) {
        this.session = session;
    }

    /**
     * Receive data from a client.
     * 
     * @param message
     */
    public void receive(WSMessage message) {
        log.trace("receive message");
        if (isConnected()) {
            WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
            WebSocketScope scope = manager.getScope(getPath());
            scope.onMessage(message);
        } else {
            log.warn("Not connected");
        }
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
        Packet packet = Packet.build(data.getBytes("UTF8"), MessageType.TEXT);
        session.write(packet);
    }

    /**
     * Sends binary data to the client.
     * 
     * @param buf
     */
    public void send(byte[] buf) {
        log.trace("send binary: {}", Arrays.toString(buf));
        Packet packet = Packet.build(buf);
        session.write(packet);
    }

    /**
     * Sends a pong back to the client; normally in response to a ping.
     * 
     * @param buf
     */
    public void sendPong(byte[] buf) {
        log.trace("send pong: {}", buf);
        Packet packet = Packet.build(buf, MessageType.PONG);
        session.write(packet);
    }

    /**
     * close Connection
     */
    public void close() {
        CloseFuture future = session.close(true);
        future.addListener(new IoFutureListener<CloseFuture>() {
            public void operationComplete(CloseFuture future) {
                if (future.isClosed()) {
                    log.debug("Connection is closed");
                } else {
                    log.debug("Connection is not yet closed");
                }
                future.removeListener(this);
                connected = false;
            }
        });
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
        return connected;
    }

    /**
     * on connected, put flg and clear keys.
     */
    public void setConnected() {
        connected = true;
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

    @Override
    public String toString() {
        return "WebSocketConnection [id=" + id + ", type=" + type + ", host=" + host + ", origin=" + origin + ", path=" + path + ", secure=" + secure + ", connected=" + connected + ", remote=" + (session != null ? session.getRemoteAddress().toString() : "unk") + "]";
    }

}
