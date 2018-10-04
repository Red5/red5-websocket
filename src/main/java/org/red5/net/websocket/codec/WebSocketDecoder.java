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

package org.red5.net.websocket.codec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.bouncycastle.util.encoders.Base64;
import org.red5.net.websocket.Constants;
import org.red5.net.websocket.WebSocketConnection;
import org.red5.net.websocket.WebSocketException;
import org.red5.net.websocket.WebSocketPlugin;
import org.red5.net.websocket.WebSocketScopeManager;
import org.red5.net.websocket.WebSocketTransport;
import org.red5.net.websocket.listener.IWebSocketDataListener;
import org.red5.net.websocket.model.ConnectionType;
import org.red5.net.websocket.model.HandshakeResponse;
import org.red5.net.websocket.model.MessageType;
import org.red5.net.websocket.model.WSMessage;
import org.red5.server.plugin.PluginRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles the websocket decoding and its handshake process. A warning is loggged if WebSocket version 13 is not detected. <br />
 * Decodes incoming buffers in a manner that makes the sender transparent to the decoders further up in the filter chain. If the sender is a native client then the buffer is simply passed through. If the sender is a websocket, it will extract the content out from the dataframe and parse it before passing it along the filter chain.
 * 
 * @see <a href="https://developer.mozilla.org/en-US/docs/WebSockets/Writing_WebSocket_servers">Mozilla - Writing WebSocket Servers</a>
 * 
 * @author Dhruv Chopra
 * @author Paul Gregoire
 */
public class WebSocketDecoder extends CumulativeProtocolDecoder {

    private static final Logger log = LoggerFactory.getLogger(WebSocketDecoder.class);

    private static final String DECODER_STATE_KEY = "decoder-state";

    private static final String DECODED_MESSAGE_KEY = "decoded-message";

    private static final String DECODED_MESSAGE_TYPE_KEY = "decoded-message-type";

    private static final String DECODED_MESSAGE_FRAGMENTS_KEY = "decoded-message-fragments";

    /**
     * Keeps track of the decoding state of a frame. Byte values start at -128 as a flag to indicate they are not set.
     */
    private final class DecoderState {
        // keep track of fin == 0 to indicate a fragment
        byte fin = Byte.MIN_VALUE;

        byte opCode = Byte.MIN_VALUE;

        byte mask = Byte.MIN_VALUE;

        int frameLen = 0;

        // payload
        byte[] payload;

        @Override
        public String toString() {
            return "DecoderState [fin=" + fin + ", opCode=" + opCode + ", mask=" + mask + ", frameLen=" + frameLen + "]";
        }
    }

    @Override
    protected boolean doDecode(IoSession session, IoBuffer in, ProtocolDecoderOutput out) throws Exception {
        IoBuffer resultBuffer;
        WebSocketConnection conn = (WebSocketConnection) session.getAttribute(Constants.CONNECTION);
        if (conn == null) {
            log.debug("Decode start pos: {}", in.position());
            // first message on a new connection, check if its from a websocket or a native socket
            if (doHandShake(session, in)) {
                log.debug("Decode end pos: {} limit: {}", in.position(), in.limit());
                // websocket handshake was successful. Don't write anything to output as we want to abstract the handshake request message from the handler
                if (in.position() != in.limit()) {
                    in.position(in.limit());
                }
                return true;
            } else if (session.containsAttribute(Constants.WS_HANDSHAKE)) {
                // more still expected to come in before HS is completed
                return false;
            } else {
                // message is from a native socket. Simply wrap and pass through
                resultBuffer = IoBuffer.wrap(in.array(), 0, in.limit());
                in.position(in.limit());
                out.write(resultBuffer);
            }
        } else if (conn.isWebConnection()) {
            // grab decoding state
            DecoderState decoderState = (DecoderState) session.getAttribute(DECODER_STATE_KEY);
            if (decoderState == null) {
                decoderState = new DecoderState();
                session.setAttribute(DECODER_STATE_KEY, decoderState);
            }
            // there is incoming data from the websocket, decode it
            decodeIncommingData(in, session);
            // this will be null until all the fragments are collected
            WSMessage message = (WSMessage) session.getAttribute(DECODED_MESSAGE_KEY);
            if (log.isDebugEnabled()) {
                log.debug("State: {} message: {}", decoderState, message);
            }
            if (message != null) {
                // set the originating connection on the message
                message.setConnection(conn);
                // write the message
                out.write(message);
                // remove decoded message
                session.removeAttribute(DECODED_MESSAGE_KEY);
            } else {
                // there was not enough data in the buffer to parse
                return false;
            }
        } else {
            // session is known to be from a native socket. So simply wrap and pass through
            byte[] arr = new byte[in.remaining()];
            in.get(arr);
            out.write(IoBuffer.wrap(arr));
        }
        return true;
    }

    /**
     * Try parsing the message as a websocket handshake request. If it is such a request, then send the corresponding handshake response (as in Section 4.2.2 RFC 6455).
     */
    @SuppressWarnings("unchecked")
    private boolean doHandShake(IoSession session, IoBuffer in) {
        if (log.isDebugEnabled()) {
            log.debug("Handshake: {}", in);
        }
        // incoming data
        byte[] data = null;
        // check for existing HS data
        if (session.containsAttribute(Constants.WS_HANDSHAKE)) {
            byte[] tmp = (byte[]) session.getAttribute(Constants.WS_HANDSHAKE);
            // size to hold existing and incoming
            data = new byte[tmp.length + in.remaining()];
            System.arraycopy(tmp, 0, data, 0, tmp.length);
            // get incoming bytes
            in.get(data, tmp.length, in.remaining());
        } else {
            // size for incoming bytes
            data = new byte[in.remaining()];
            // get incoming bytes
            in.get(data);
        }
        // ensure the incoming data is complete (ends with crlfcrlf)
        byte[] tail = Arrays.copyOfRange(data, data.length - 4, data.length);
        if (!Arrays.equals(tail, Constants.END_OF_REQ)) {
            // accumulate the HS data
            session.setAttribute(Constants.WS_HANDSHAKE, data);
            return false;
        }
        // create the connection obj
        WebSocketConnection conn = new WebSocketConnection(session);
        // mark as secure if using ssl
        if (session.getFilterChain().contains("sslFilter")) {
            conn.setSecure(true);
        }
        try {
            Map<String, Object> headers = parseClientRequest(conn, new String(data));
            if (log.isTraceEnabled()) {
                log.trace("Header map: {}", headers);
            }
            if (!headers.isEmpty() && headers.containsKey(Constants.WS_HEADER_KEY)) {
                // add the headers to the connection, they may be of use to implementers
                conn.setHeaders(headers);
                // add query string parameters
                if (headers.containsKey(Constants.URI_QS_PARAMETERS)) {
                    conn.setQuerystringParameters((Map<String, Object>) headers.remove(Constants.URI_QS_PARAMETERS));
                }
                // check the version
                if (!"13".equals(headers.get(Constants.WS_HEADER_VERSION))) {
                    log.info("Version 13 was not found in the request, communications may fail");
                }
                // get the path 
                String path = conn.getPath();
                // get the scope manager
                WebSocketScopeManager manager = (WebSocketScopeManager) session.getAttribute(Constants.MANAGER);
                if (manager == null) {
                    WebSocketPlugin plugin = (WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin");
                    manager = plugin.getManager(path);
                }
                // store manager in the current session
                session.setAttribute(Constants.MANAGER, manager);
                // TODO add handling for extensions

                // TODO expand handling for protocols requested by the client, instead of just echoing back
                if (headers.containsKey(Constants.WS_HEADER_PROTOCOL)) {
                    boolean protocolSupported = false;
                    String protocol = (String) headers.get(Constants.WS_HEADER_PROTOCOL);
                    log.debug("Protocol '{}' found in the request", protocol);
                    // add protocol to the connection
                    conn.setProtocol(protocol);
                    // TODO check listeners for "protocol" support
                    Set<IWebSocketDataListener> listeners = manager.getScope(path).getListeners();
                    for (IWebSocketDataListener listener : listeners) {
                        if (listener.getProtocol().equals(protocol)) {
                            //log.debug("Scope has listener support for the {} protocol", protocol);
                            protocolSupported = true;
                            break;
                        }
                    }
                    log.debug("Scope listener does{} support the '{}' protocol", (protocolSupported ? "" : "n't"), protocol);
                }
                // add connection to the manager
                manager.addConnection(conn);
                // prepare response and write it to the directly to the session
                HandshakeResponse wsResponse = buildHandshakeResponse(conn, (String) headers.get(Constants.WS_HEADER_KEY));
                // pass the handshake response to the ws connection so it can be sent outside the io thread and allow the decode to complete
                conn.sendHandshakeResponse(wsResponse);
                // remove the chunk attr
                session.removeAttribute(Constants.WS_HANDSHAKE);
                return true;
            }
            // set connection as native / direct
            conn.setType(ConnectionType.DIRECT);
        } catch (Exception e) {
            // input is not a websocket handshake request
            log.warn("Handshake failed", e);
        }
        return false;
    }

    /**
     * Parse the client request and return a map containing the header contents. If the requested application is not enabled, return a 400 error.
     * 
     * @param conn
     * @param requestData
     * @return map of headers
     * @throws WebSocketException
     */
    private Map<String, Object> parseClientRequest(WebSocketConnection conn, String requestData) throws WebSocketException {
        String[] request = requestData.split("\r\n");
        if (log.isDebugEnabled()) {
            log.debug("Request: {}", Arrays.toString(request));
        }
        // host and origin for validation purposes
        String host = null, origin = null;
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < request.length; i++) {
            log.trace("Request {}: {}", i, request[i]);
            if (request[i].startsWith("GET ") || request[i].startsWith("POST ") || request[i].startsWith("PUT ")) {
                // "GET /chat/room1?id=publisher1 HTTP/1.1"
                // split it on space
                String requestPath = request[i].split("\\s+")[1];
                // get the path data for handShake
                int start = requestPath.indexOf('/');
                int end = requestPath.length();
                int ques = requestPath.indexOf('?');
                if (ques > 0) {
                    end = ques;
                }
                log.trace("Request path: {} to {} ques: {}", start, end, ques);
                String path = requestPath.substring(start, end).trim();
                log.trace("Client request path: {}", path);
                conn.setPath(path);
                // check for '?' or included query string
                if (ques > 0) {
                    // parse any included query string
                    String qs = requestPath.substring(ques).trim();
                    log.trace("Request querystring: {}", qs);
                    map.put(Constants.URI_QS_PARAMETERS, parseQuerystring(qs));
                }
                // get the manager
                WebSocketPlugin plugin = (WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin");
                if (plugin != null) {
                    log.trace("Found plugin");
                    WebSocketScopeManager manager = plugin.getManager(path);
                    log.trace("Manager was found? : {}", manager);
                    // only check that the application is enabled, not the room or sub levels
                    if (manager != null && manager.isEnabled(path)) {
                        log.trace("Path enabled: {}", path);
                    } else {
                        // invalid scope or its application is not enabled, send disconnect message
                        conn.close(1002, build400Response(conn));
                        throw new WebSocketException("Handshake failed, path not enabled");
                    }
                } else {
                    log.warn("Plugin lookup failed");
                    conn.close(1002, build400Response(conn));
                    throw new WebSocketException("Handshake failed, missing plugin");
                }
            } else if (request[i].contains(Constants.WS_HEADER_KEY)) {
                map.put(Constants.WS_HEADER_KEY, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.WS_HEADER_VERSION)) {
                map.put(Constants.WS_HEADER_VERSION, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.WS_HEADER_EXTENSIONS)) {
                map.put(Constants.WS_HEADER_EXTENSIONS, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.WS_HEADER_PROTOCOL)) {
                map.put(Constants.WS_HEADER_PROTOCOL, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.HTTP_HEADER_HOST)) {
                // get the host data
                host = extractHeaderValue(request[i]);
                conn.setHost(host);
            } else if (request[i].contains(Constants.HTTP_HEADER_ORIGIN)) {
                // get the origin data
                origin = extractHeaderValue(request[i]);
                conn.setOrigin(origin);
            } else if (request[i].contains(Constants.HTTP_HEADER_USERAGENT)) {
                map.put(Constants.HTTP_HEADER_USERAGENT, extractHeaderValue(request[i]));
            } else if (request[i].startsWith(Constants.WS_HEADER_GENERIC_PREFIX)) {
                map.put(getHeaderName(request[i]), extractHeaderValue(request[i]));
            }
        }
        // policy checking
        boolean validOrigin = true;
        if (conn.isSameOriginPolicy()) {
            // if SOP / origin validation is enabled, verify the origin
            String trimmedHost = host;
            // strip protocol if its there
            if (host.startsWith("http")) {
                trimmedHost = host.substring(host.indexOf("//") + 1);
            }
            // chop off port etc..
            int colonIndex = trimmedHost.indexOf(':');
            if (colonIndex > 0) {
                trimmedHost = trimmedHost.substring(0, colonIndex);
            }
            log.debug("Trimmed host: {}", trimmedHost);
            validOrigin = origin.contains(trimmedHost);
            log.debug("Same Origin? {}", validOrigin);
        }
        if (conn.isCrossOriginPolicy()) {
            // if CORS is enabled
            validOrigin = conn.isValidOrigin(origin);
            log.debug("Origin {} valid? {}", origin, validOrigin);
        }
        if (!validOrigin) {
            conn.close(1008, build403Response(conn));
            throw new WebSocketException(String.format("Policy failure - SOP enabled: %b CORS enabled: %b", WebSocketTransport.isSameOriginPolicy(), WebSocketTransport.isCrossOriginPolicy()));
        } else {
            log.debug("Origin is valid");
        }
        return map;
    }

    /**
     * Returns the trimmed header name.
     * 
     * @param requestHeader
     * @return value
     */
    private String getHeaderName(String requestHeader) {
        return requestHeader.substring(0, requestHeader.indexOf(':')).trim();
    }

    /**
     * Returns the trimmed header value.
     * 
     * @param requestHeader
     * @return value
     */
    private String extractHeaderValue(String requestHeader) {
        return requestHeader.substring(requestHeader.indexOf(':') + 1).trim();
    }

    /**
     * Build a handshake response based on the given client key.
     * 
     * @param clientKey
     * @return response
     * @throws WebSocketException
     */
    private HandshakeResponse buildHandshakeResponse(WebSocketConnection conn, String clientKey) throws WebSocketException {
        if (log.isDebugEnabled()) {
            log.debug("buildHandshakeResponse: {} client key: {}", conn, clientKey);
        }
        byte[] accept;
        try {
            // performs the accept creation routine from RFC6455 @see <a href="http://tools.ietf.org/html/rfc6455">RFC6455</a>
            // concatenate the key and magic string, then SHA1 hash and base64 encode
            MessageDigest md = MessageDigest.getInstance("SHA1");
            accept = Base64.encode(md.digest((clientKey + Constants.WEBSOCKET_MAGIC_STRING).getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new WebSocketException("Algorithm is missing");
        }
        // make up reply data...
        IoBuffer buf = IoBuffer.allocate(308);
        buf.setAutoExpand(true);
        buf.put("HTTP/1.1 101 Switching Protocols".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Upgrade: websocket".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Connection: Upgrade".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Server: Red5".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Sec-WebSocket-Version-Server: 13".getBytes());
        buf.put(Constants.CRLF);
        buf.put(String.format("Sec-WebSocket-Origin: %s", conn.getOrigin()).getBytes());
        buf.put(Constants.CRLF);
        buf.put(String.format("Sec-WebSocket-Location: %s", conn.getHost()).getBytes());
        buf.put(Constants.CRLF);
        // send back extensions if enabled
        if (conn.hasExtensions()) {
            buf.put(String.format("Sec-WebSocket-Extensions: %s", conn.getExtensionsAsString()).getBytes());
            buf.put(Constants.CRLF);
        }
        // send back protocol if enabled
        if (conn.hasProtocol()) {
            buf.put(String.format("Sec-WebSocket-Protocol: %s", conn.getProtocol()).getBytes());
            buf.put(Constants.CRLF);
        }
        buf.put(String.format("Sec-WebSocket-Accept: %s", new String(accept)).getBytes());
        buf.put(Constants.CRLF);
        buf.put(Constants.CRLF);
        // if any bytes follow this crlf, the follow-up data will be corrupted
        if (log.isTraceEnabled()) {
            log.trace("Handshake response size: {}", buf.limit());
        }
        return new HandshakeResponse(buf);
    }

    /**
     * Build an HTTP 400 "Bad Request" response.
     * 
     * @return response
     * @throws WebSocketException
     */
    private HandshakeResponse build400Response(WebSocketConnection conn) throws WebSocketException {
        if (log.isDebugEnabled()) {
            log.debug("build400Response: {}", conn);
        }
        // make up reply data...
        IoBuffer buf = IoBuffer.allocate(32);
        buf.setAutoExpand(true);
        buf.put("HTTP/1.1 400 Bad Request".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Sec-WebSocket-Version-Server: 13".getBytes());
        buf.put(Constants.CRLF);
        buf.put(Constants.CRLF);
        if (log.isTraceEnabled()) {
            log.trace("Handshake error response size: {}", buf.limit());
        }
        return new HandshakeResponse(buf);
    }

    /**
     * Build an HTTP 403 "Forbidden" response.
     * 
     * @return response
     * @throws WebSocketException
     */
    private HandshakeResponse build403Response(WebSocketConnection conn) throws WebSocketException {
        if (log.isDebugEnabled()) {
            log.debug("build403Response: {}", conn);
        }
        // make up reply data...
        IoBuffer buf = IoBuffer.allocate(32);
        buf.setAutoExpand(true);
        buf.put("HTTP/1.1 403 Forbidden".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Sec-WebSocket-Version-Server: 13".getBytes());
        buf.put(Constants.CRLF);
        buf.put(Constants.CRLF);
        if (log.isTraceEnabled()) {
            log.trace("Handshake error response size: {}", buf.limit());
        }
        return new HandshakeResponse(buf);
    }

    /**
     * Decode the in buffer according to the Section 5.2. RFC 6455. If there are multiple websocket dataframes in the buffer, this will parse all and return one complete decoded buffer.
     * 
     * <pre>
     * 	  0                   1                   2                   3
     * 	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * 	 +-+-+-+-+-------+-+-------------+-------------------------------+
     * 	 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     * 	 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     * 	 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     * 	 | |1|2|3|       |K|             |                               |
     * 	 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     * 	 |     Extended payload length continued, if payload len == 127  |
     * 	 + - - - - - - - - - - - - - - - +-------------------------------+
     * 	 |                               |Masking-key, if MASK set to 1  |
     * 	 +-------------------------------+-------------------------------+
     * 	 | Masking-key (continued)       |          Payload Data         |
     * 	 +-------------------------------- - - - - - - - - - - - - - - - +
     * 	 :                     Payload Data continued ...                :
     * 	 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     * 	 |                     Payload Data continued ...                |
     * 	 +---------------------------------------------------------------+
     * </pre>
     * 
     * @param in
     * @param session
     */
    public static void decodeIncommingData(IoBuffer in, IoSession session) {
        log.trace("Decoding: {}", in);
        // get decoder state
        DecoderState decoderState = (DecoderState) session.getAttribute(DECODER_STATE_KEY);
        if (decoderState.fin == Byte.MIN_VALUE) {
            byte frameInfo = in.get();
            // get FIN (1 bit)
            //log.debug("frameInfo: {}", Integer.toBinaryString((frameInfo & 0xFF) + 256));
            decoderState.fin = (byte) ((frameInfo >>> 7) & 1);
            log.trace("FIN: {}", decoderState.fin);
            // the next 3 bits are for RSV1-3 (not used here at the moment)			
            // get the opcode (4 bits)
            decoderState.opCode = (byte) (frameInfo & 0x0f);
            log.trace("Opcode: {}", decoderState.opCode);
            // opcodes 3-7 and b-f are reserved for non-control frames
        }
        if (decoderState.mask == Byte.MIN_VALUE) {
            byte frameInfo2 = in.get();
            // get mask bit (1 bit)
            decoderState.mask = (byte) ((frameInfo2 >>> 7) & 1);
            log.trace("Mask: {}", decoderState.mask);
            // get payload length (7, 7+16, 7+64 bits)
            decoderState.frameLen = (frameInfo2 & (byte) 0x7F);
            log.trace("Payload length: {}", decoderState.frameLen);
            if (decoderState.frameLen == 126) {
                decoderState.frameLen = in.getUnsignedShort();
                log.trace("Payload length updated: {}", decoderState.frameLen);
            } else if (decoderState.frameLen == 127) {
                long extendedLen = in.getLong();
                if (extendedLen >= Integer.MAX_VALUE) {
                    log.error("Data frame is too large for this implementation. Length: {}", extendedLen);
                } else {
                    decoderState.frameLen = (int) extendedLen;
                }
                log.trace("Payload length updated: {}", decoderState.frameLen);
            }
        }
        // ensure enough bytes left to fill payload, if masked add 4 additional bytes
        if (decoderState.frameLen + (decoderState.mask == 1 ? 4 : 0) > in.remaining()) {
            log.info("Not enough data available to decode, socket may be closed/closing");
        } else {
            // if the data is masked (xor'd)
            if (decoderState.mask == 1) {
                // get the mask key
                byte maskKey[] = new byte[4];
                for (int i = 0; i < 4; i++) {
                    maskKey[i] = in.get();
                }
                /*  now un-mask frameLen bytes as per Section 5.3 RFC 6455
                Octet i of the transformed data ("transformed-octet-i") is the XOR of
                octet i of the original data ("original-octet-i") with octet at index
                i modulo 4 of the masking key ("masking-key-octet-j"):
                j                   = i MOD 4
                transformed-octet-i = original-octet-i XOR masking-key-octet-j
                */
                decoderState.payload = new byte[decoderState.frameLen];
                for (int i = 0; i < decoderState.frameLen; i++) {
                    byte maskedByte = in.get();
                    decoderState.payload[i] = (byte) (maskedByte ^ maskKey[i % 4]);
                }
            } else {
                decoderState.payload = new byte[decoderState.frameLen];
                in.get(decoderState.payload);
            }
            // if FIN == 0 we have fragments
            if (decoderState.fin == 0) {
                // store the fragment and continue
                IoBuffer fragments = (IoBuffer) session.getAttribute(DECODED_MESSAGE_FRAGMENTS_KEY);
                if (fragments == null) {
                    fragments = IoBuffer.allocate(decoderState.frameLen);
                    fragments.setAutoExpand(true);
                    session.setAttribute(DECODED_MESSAGE_FRAGMENTS_KEY, fragments);
                    // store message type since following type may be a continuation
                    MessageType messageType = MessageType.CLOSE;
                    switch (decoderState.opCode) {
                        case 0: // continuation
                            messageType = MessageType.CONTINUATION;
                            break;
                        case 1: // text
                            messageType = MessageType.TEXT;
                            break;
                        case 2: // binary
                            messageType = MessageType.BINARY;
                            break;
                        case 9: // ping
                            messageType = MessageType.PING;
                            break;
                        case 0xa: // pong
                            messageType = MessageType.PONG;
                            break;
                    }
                    session.setAttribute(DECODED_MESSAGE_TYPE_KEY, messageType);
                }
                fragments.put(decoderState.payload);
                // remove decoder state
                session.removeAttribute(DECODER_STATE_KEY);
            } else {
                // create a message
                WSMessage message = new WSMessage();
                // check for previously set type from the first fragment (if we have fragments)
                MessageType messageType = (MessageType) session.getAttribute(DECODED_MESSAGE_TYPE_KEY);
                if (messageType == null) {
                    switch (decoderState.opCode) {
                        case 0: // continuation
                            messageType = MessageType.CONTINUATION;
                            break;
                        case 1: // text
                            messageType = MessageType.TEXT;
                            break;
                        case 2: // binary
                            messageType = MessageType.BINARY;
                            break;
                        case 9: // ping
                            messageType = MessageType.PING;
                            break;
                        case 0xa: // pong
                            messageType = MessageType.PONG;
                            break;
                        case 8: // close
                            messageType = MessageType.CLOSE;
                            // handler or listener should close upon receipt
                            break;
                        default:
                            // TODO throw ex?
                            log.info("Unhandled opcode: {}", decoderState.opCode);
                    }
                }
                // set message type
                message.setMessageType(messageType);
                // check for fragments and piece them together, otherwise just send the single completed frame
                IoBuffer fragments = (IoBuffer) session.removeAttribute(DECODED_MESSAGE_FRAGMENTS_KEY);
                if (fragments != null) {
                    fragments.put(decoderState.payload);
                    fragments.flip();
                    message.setPayload(fragments);
                } else {
                    // add the payload
                    message.addPayload(decoderState.payload);
                }
                // set the message on the session
                session.setAttribute(DECODED_MESSAGE_KEY, message);
                // remove decoder state
                session.removeAttribute(DECODER_STATE_KEY);
                // remove type
                session.removeAttribute(DECODED_MESSAGE_TYPE_KEY);
            }
        }
    }

    /**
     * Returns a map of key / value pairs from a given querystring.
     * 
     * @param query
     * @return k/v map
     */
    public static Map<String, Object> parseQuerystring(String query) {
        String[] params = query.split("&");
        Map<String, Object> map = new HashMap<String, Object>();
        for (String param : params) {
            String[] nameValue = param.split("=");
            map.put(nameValue[0], nameValue[1]);
        }
        return map;
    }

}
