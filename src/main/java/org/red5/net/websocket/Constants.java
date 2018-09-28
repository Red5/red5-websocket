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

import org.apache.mina.core.buffer.IoBuffer;

/**
 * Convenience class for holding constants.
 * 
 * @author Paul Gregoire
 */
public class Constants {

    public static final String MANAGER = "ws.manager";

    public static final String SCOPE = "ws.scope";

    public final static String CONNECTION = "ws.connection";

    public final static String SESSION = "session";

    public static final Object WS_HANDSHAKE = "ws.handshake";

    public final static String WS_HEADER_KEY = "Sec-WebSocket-Key";

    public final static String WS_HEADER_VERSION = "Sec-WebSocket-Version";

    public final static String WS_HEADER_EXTENSIONS = "Sec-WebSocket-Extensions";

    public final static String WS_HEADER_PROTOCOL = "Sec-WebSocket-Protocol";

    public final static String HTTP_HEADER_HOST = "Host";

    public final static String HTTP_HEADER_ORIGIN = "Origin";

    public final static String HTTP_HEADER_USERAGENT = "User-Agent";
    
    public final static String WS_HEADER_FORWARDED = "X-Forwarded-For";
    
    public final static String WS_HEADER_REAL_IP = "X-Real-IP";
    
    public final static String WS_HEADER_GENERIC_PREFIX = "X-";

    public static final String URI_QS_PARAMETERS = "querystring-parameters";

    // used to determine if close message was written
    public static final String STATUS_CLOSE_WRITTEN = "close.written";
    
    // magic string for websockets
    public static final String WEBSOCKET_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public static final byte[] CRLF = { 0x0d, 0x0a };

    public static final byte[] END_OF_REQ = { 0x0d, 0x0a, 0x0d, 0x0a };

    // simple text content to go with our close message / packet
    public static final byte[] CLOSE_MESSAGE_BYTES;

    public static final Boolean HANDSHAKE_COMPLETE = Boolean.TRUE;

    public static final String IDLE_COUNTER = "idle.counter";
    
    static {
        IoBuffer buf = IoBuffer.allocate(16);
        buf.setAutoExpand(true);
        // 2 byte unsigned code per rfc6455 5.5.1
        buf.putUnsigned((short) 1000); // normal close
        // this should never fail, but never say never...
        try {
            buf.put("Normal close".getBytes("UTF8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        buf.flip();
        CLOSE_MESSAGE_BYTES = new byte[buf.remaining()];
        buf.get(CLOSE_MESSAGE_BYTES);
    }
    
}
