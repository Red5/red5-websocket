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

package org.red5.net.websocket.codec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.IoFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.bouncycastle.util.encoders.Base64;
import org.red5.net.websocket.Constants;
import org.red5.net.websocket.WebSocketConnection;
import org.red5.net.websocket.WebSocketException;
import org.red5.net.websocket.WebSocketPlugin;
import org.red5.net.websocket.WebSocketScopeManager;
import org.red5.net.websocket.model.ConnectionType;
import org.red5.net.websocket.model.HandshakeResponse;
import org.red5.net.websocket.model.MessageType;
import org.red5.net.websocket.model.WSMessage;
import org.red5.server.plugin.PluginRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles the websocket decoding and its handshake process. A warning is loggged if WebSocket version 13 is not detected.
 * <br />
 * Decodes incoming buffers in a manner that makes the sender transparent to the decoders further up in the filter chain. If the sender is a native client then
 * the buffer is simply passed through. If the sender is a websocket, it will extract the content out from the dataframe and parse it before passing it along the filter
 * chain.
 * 
 * @see <a href="https://developer.mozilla.org/en-US/docs/WebSockets/Writing_WebSocket_servers">Mozilla - Writing WebSocket Servers</a>
 * 
 * @author Dhruv Chopra
 * @author Paul Gregoire
 */
public class WebSocketDecoder extends CumulativeProtocolDecoder {

	private static final Logger log = LoggerFactory.getLogger(WebSocketDecoder.class);

	@Override
	protected boolean doDecode(IoSession session, IoBuffer in, ProtocolDecoderOutput out) throws Exception {
		IoBuffer resultBuffer;
		WebSocketConnection conn = (WebSocketConnection) session.getAttribute(Constants.CONNECTION);
		if (conn == null) {
			// first message on a new connection, check if its from a websocket or a native socket
			if (doHandShake(session, in)) {
				// websocket handshake was successful. Don't write anything to output as we want to abstract the handshake request message from the handler
				in.position(in.limit());
				return true;
			} else {
				// message is from a native socket. Simply wrap and pass through
				resultBuffer = IoBuffer.wrap(in.array(), 0, in.limit());
				in.position(in.limit());
				out.write(resultBuffer);
			}
		} else if (conn.isWebConnection()) {
			// there is incoming data from the websocket, decode and send to handler or next filter     
			int startPos = in.position();
			WSMessage message = decodeIncommingData(in, session);
			if (message.isPayloadComplete()) {				
				out.write(message);
			} else {
				// there was not enough data in the buffer to parse. Reset the in buffer position and wait for more data before trying again
				in.position(startPos);
				return false;
			}
		} else {
			// session is known to be from a native socket. So simply wrap and pass through
			resultBuffer = IoBuffer.wrap(in.array(), 0, in.limit());
			in.position(in.limit());
			out.write(resultBuffer);
		}
		return true;
	}

	/**
	 * Try parsing the message as a websocket handshake request. If it is such a request, 
	 * then send the corresponding handshake response (as in Section 4.2.2 RFC 6455).
	 */
	private boolean doHandShake(IoSession session, IoBuffer in) {
		// create the connection obj
		WebSocketConnection conn = new WebSocketConnection(session);
		try {
			Map<String, String> headers = parseClientRequest(conn, new String(in.array()));
	        log.warn("Header map: {}", headers);			
			if (!headers.isEmpty() && headers.containsKey(Constants.WS_HEADER_KEY)) {
				// add the headers to the connection, they may be of use to implementers
				conn.setHeaders(headers);
				// check the version
				if (!"13".equals(headers.get(Constants.WS_HEADER_VERSION))) {
					log.info("Version 13 was not found in the request, handshaking may fail");
				}  
				// TODO add handling for protocols requested by the client
				
				// store connection in the current session
				session.setAttribute("connection", conn);
				// handshake is finished
				conn.setConnected();
				// add connection to the manager
				WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
				manager.addConnection(conn);
				// prepare response and write it to the directly to the session
				HandshakeResponse wsResponse = buildHandshakeResponse(conn, headers.get(Constants.WS_HEADER_KEY));		
				session.write(wsResponse);
				log.debug("Handshake complete");				
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
	 * Parse the client request and return a map containing the header contents. If the requested application is not enabled, return 
	 * a 400 error.
	 * 
	 * @param conn
	 * @param requestData
	 * @return map of headers
	 * @throws WebSocketException
	 */
    private Map<String, String> parseClientRequest(WebSocketConnection conn, String requestData) throws WebSocketException {
        String[] request = requestData.split("\r\n");
        log.warn("Request: {}", Arrays.toString(request));
        Map<String, String> map = new HashMap<String, String>();
        for (int i = 0; i < request.length; i++) {
        	if (request[i].startsWith("GET ")) {
				// get the path data for handShake
        		int start = request[i].indexOf('/');
        		int end = request[i].indexOf(' ', start);
        		// check for '?' or included query string
        		if (request[i].indexOf('?', start) > 0) {
        			end = request[i].indexOf('?', start);
    				// parse any included query string
        			
        		}
				String path = request[i].substring(start, end).trim();
				conn.setPath(path);				
				// get the manager
				WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
				// only check that the application is enabled, not the room or sub levels
				if (!manager.isEnabled(path)) {
					// invalid scope or its application is not enabled, send disconnect message
					HandshakeResponse errResponse = build400Response(conn);		
					WriteFuture future = conn.getSession().write(errResponse);
					future.addListener(new IoFutureListener<IoFuture>() {
						@Override
						public void operationComplete(IoFuture future) {
							// close connection
							future.getSession().close(false);
						}
					});
					throw new WebSocketException("Handshake failed");
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
				conn.setHost(extractHeaderValue(request[i]));
			} else if (request[i].contains(Constants.HTTP_HEADER_ORIGIN)) {
				// get the origin data
				conn.setOrigin(extractHeaderValue(request[i]));
			} else if (request[i].contains(Constants.HTTP_HEADER_USERAGENT)) {
				map.put(Constants.HTTP_HEADER_USERAGENT, extractHeaderValue(request[i]));
			}
        }
        return map;
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
		buf.put(("Sec-WebSocket-Origin: " + conn.getOrigin()).getBytes());
		buf.put(Constants.CRLF);
		buf.put(String.format("Sec-WebSocket-Location: %s", conn.getHost()).getBytes());
		buf.put(Constants.CRLF);
		buf.put(String.format("Sec-WebSocket-Accept: %s", new String(accept)).getBytes());
		buf.put(Constants.CRLF);
		buf.put("Sec-WebSocket-Version-Server: 13".getBytes());
		buf.put(Constants.CRLF);
		buf.put("Server: Red5".getBytes());
		buf.put(Constants.CRLF);
		buf.put(Constants.CRLF);
		buf.put(accept);
		log.trace("Handshake response size: {}", buf.limit());
		return new HandshakeResponse(buf);
	}
	
	/**
	 * Build an HTTP 400 "Bad Request" response.
	 * 
	 * @return response
	 * @throws WebSocketException 
	 */
	private HandshakeResponse build400Response(WebSocketConnection conn) throws WebSocketException {
		// make up reply data...
		IoBuffer buf = IoBuffer.allocate(32);
		buf.setAutoExpand(true);
		buf.put("HTTP/1.1 400 Bad Request".getBytes());
		buf.put(Constants.CRLF);
		buf.put("Sec-WebSocket-Version-Server: 13".getBytes());
		buf.put(Constants.CRLF);
		buf.put(Constants.CRLF);
		log.trace("Handshake error response size: {}", buf.limit());
		return new HandshakeResponse(buf);
	}	
	
	/**
	 * Decode the in buffer according to the Section 5.2. RFC 6455.
	 * If there are multiple websocket dataframes in the buffer, this will parse all and return one complete decoded buffer.
	 * <pre>
	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-------+-+-------------+-------------------------------+
	 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
	 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
	 | |1|2|3|       |K|             |                               |
	 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	 |     Extended payload length continued, if payload len == 127  |
	 + - - - - - - - - - - - - - - - +-------------------------------+
	 |                               |Masking-key, if MASK set to 1  |
	 +-------------------------------+-------------------------------+
	 | Masking-key (continued)       |          Payload Data         |
	 +-------------------------------- - - - - - - - - - - - - - - - +
	 :                     Payload Data continued ...                :
	 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	 |                     Payload Data continued ...                |
	 +---------------------------------------------------------------+
	 * </pre>
	 * 
	 * @param in
	 * @param session
	 * @return IoBuffer
	 */
	public static WSMessage decodeIncommingData(IoBuffer in, IoSession session) {
		WSMessage result = new WSMessage();
		do {
			byte frameInfo = in.get();
			// get FIN (1 bit)
			byte fin = (byte) ((frameInfo >> 7) & 1);
			log.trace("FIN: {}", fin);
			// the next 3 bits are for RSV1-3 (not used here at the moment)			
			// get the opcode (4 bits)
			byte opCode = (byte) (frameInfo & 0x0f);
			log.trace("Opcode: {}", opCode);
			// opcodes 3-7 and b-f are reserved for non-control frames
			switch (opCode) {
				case 0: // continuation
					result.setMessageType(MessageType.CONTINUATION);
					break;
				case 1: // text
					result.setMessageType(MessageType.TEXT);
					break;
				case 2: // binary
					result.setMessageType(MessageType.BINARY);					
					break;
				case 9: // ping
					log.trace("PING");
					result.setMessageType(MessageType.PING);
					// TODO should send back a PONG
					
					break;
				case 0xa: // pong
					log.trace("PONG");					
					result.setMessageType(MessageType.PONG);
					break;
				case 8: // close
					result.setMessageType(MessageType.CLOSE);
					// close the session without delay
					session.close(true);
					return result;				
				default:
					log.info("Unhandled opcode: {}", opCode);					
			}
			byte frameInfo2 = in.get();
			// get mask bit (1 bit)
			byte mask = (byte) ((frameInfo2 >> 7) & 1);
			log.trace("Mask: {}", mask);
			// get payload length (7, 7+16, 7+64 bits)
			int frameLen = (frameInfo2 & (byte) 0x7F);
			log.trace("Payload length: {}", frameLen);
			if (frameLen == 126) {
				frameLen = in.getShort();
				log.trace("Payload length updated: {}", frameLen);
			}
			if (frameLen == 127) {
				long extendedLen = in.getLong();
				if (extendedLen >= Integer.MAX_VALUE) {
					log.error("Data frame is too large for this implementation. Length: {}", extendedLen);
				} else {
					frameLen = (int) extendedLen;
				}
				log.trace("Payload length updated: {}", frameLen);
			}
			// if the data is masked (xor'd)
			if (mask == 1) {
				// Validate if we have enough data in the buffer to completely parse the WebSocket DataFrame. If not return null.
				if (frameLen + 4 > in.remaining()) {
					log.warn("Not enough data available to decode");
					return null;
				}
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
    			byte[] unMaskedPayLoad = new byte[frameLen];
    			for (int i = 0; i < frameLen; i++) {
    				byte maskedByte = in.get();
    				unMaskedPayLoad[i] = (byte) (maskedByte ^ maskKey[i % 4]);
    			}
    			// add the payload
    			result.addPayload(unMaskedPayLoad);
			} else {
				// Validate if we have enough data in the buffer to completely parse the WebSocket DataFrame. If not return null.
				if (frameLen > in.remaining()) {
					log.warn("Not enough data available to decode");
					return null;
				}
				byte[] payLoad = new byte[frameLen];
    			in.get(payLoad);
    			// add the payload
    			result.addPayload(payLoad);
			}
		} while (in.hasRemaining());
		result.setPayloadComplete();
		return result;
	}
	
}