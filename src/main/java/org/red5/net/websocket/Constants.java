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

    public final static String WS_HEADER_KEY = "Sec-WebSocket-Key";

    public final static String WS_HEADER_VERSION = "Sec-WebSocket-Version";

    public final static String WS_HEADER_EXTENSIONS = "Sec-WebSocket-Extensions";

    public final static String WS_HEADER_PROTOCOL = "Sec-WebSocket-Protocol";

    public final static String HTTP_HEADER_HOST = "Host";

    public final static String HTTP_HEADER_ORIGIN = "Origin";

    public final static String HTTP_HEADER_USERAGENT = "User-Agent";

    public static final String URI_QS_PARAMETERS = "querystring-parameters";

    // magic string for websockets
    public static final String WEBSOCKET_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public static final byte[] CRLF = { 0x0D, 0x0A };
}
