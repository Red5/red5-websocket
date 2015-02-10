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

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoderAdapter;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;
import org.red5.net.websocket.Constants;
import org.red5.net.websocket.WebSocketConnection;
import org.red5.net.websocket.model.HandshakeRequest;
import org.red5.net.websocket.model.HandshakeResponse;
import org.red5.net.websocket.model.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encodes incoming buffers in a manner that makes the receiving client type transparent to the encoders further up in the filter chain. 
 * If the receiving client is a native client then the buffer contents are simply passed through. If the receiving client is a websocket, 
 * it will encode the buffer contents in to WebSocket DataFrame before passing it along the filter chain.
 * 
 * <i>Note: you must wrap the IoBuffer you want to send around a WebSocketCodecPacket instance.</i>
 * 
 * @author Dhruv Chopra
 * @author Paul Gregoire
 */
public class WebSocketEncoder extends ProtocolEncoderAdapter {

	private static final Logger log = LoggerFactory.getLogger(WebSocketEncoder.class);
	
	@Override
	public void encode(IoSession session, Object message, ProtocolEncoderOutput out) throws Exception {
		WebSocketConnection conn = (WebSocketConnection) session.getAttribute(Constants.CONNECTION);
		IoBuffer resultBuffer;
		if (message instanceof Packet) {
			Packet packet = (Packet) message;
			// if the connection is not native / direct, add websocket encoding
			resultBuffer = conn.isWebConnection() ? encodeOutgoingData(packet) : packet.getData();
		} else if (message instanceof HandshakeResponse) {
			HandshakeResponse resp = (HandshakeResponse) message;
			resultBuffer = resp.getResponse();
		} else if (message instanceof HandshakeRequest) {
			HandshakeRequest req = (HandshakeRequest) message;
			resultBuffer = req.getRequest();
		} else {
			throw new Exception("message not a websocket type");
		}
		out.write(resultBuffer);
	}

	// Encode the in buffer according to the Section 5.2. RFC 6455
	public static IoBuffer encodeOutgoingData(Packet packet) {
		log.debug("encode outgoing: {}", packet);
		// get the payload data
		IoBuffer data = packet.getData();
		// get the frame length based on the byte count
		int frameLen = data.limit(); 
		// start with frame length + 2b (header info)
		IoBuffer buffer = IoBuffer.allocate(frameLen + 2, false);
		buffer.setAutoExpand(true);
		// set the proper flags / opcode for the data
		byte frameInfo = (byte) (1 << 7);
		switch (packet.getType()) {
			case TEXT:
				log.trace("Encoding text frame");
				frameInfo = (byte) (frameInfo | 1);
				break;
			case BINARY:
				log.trace("Encoding binary frame");
				frameInfo = (byte) (frameInfo | 2);
				break;
			case CLOSE:
				frameInfo = (byte) (frameInfo | 8);
				break;
			case CONTINUATION:
				frameInfo = (byte) (frameInfo | 0);				
				break;
			case PING:
				frameInfo = (byte) (frameInfo | 9);
				break;
			case PONG:
				frameInfo = (byte) (frameInfo | 0xa);
				break;
			default:
				break;
		}
		buffer.put(frameInfo);		
		// set the frame length
		if (frameLen <= 125) {
			buffer.put((byte) ((byte) frameLen & (byte) 0x7F));
		} else if (frameLen > 125 && frameLen <= 65535) {
			buffer.put((byte) ((byte) 126 & (byte) 0x7F));
			buffer.putShort((short) frameLen);
		} else {
			buffer.put((byte) ((byte) 127 & (byte) 0x7F));
			buffer.putLong((int) frameLen);
		}
		buffer.put(data);
		buffer.flip();
		if (log.isTraceEnabled()) {
			log.trace("Encoded: {}", buffer);
		}
		return buffer;
	}

}
