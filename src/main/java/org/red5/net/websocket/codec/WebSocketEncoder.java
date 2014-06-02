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
import org.red5.net.websocket.model.HandshakeResponse;
import org.red5.net.websocket.model.Packet;

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

	@Override
	public void encode(IoSession session, Object message, ProtocolEncoderOutput out) throws Exception {
		WebSocketConnection conn = (WebSocketConnection) session.getAttribute(Constants.CONNECTION);
		IoBuffer resultBuffer;
		if (message instanceof Packet) {
			Packet packet = (Packet) message;
			// if the connection is not native / direct, add websocket encoding
			resultBuffer = conn.isWebConnection() ? encodeOutgoingData(packet.getData()) : packet.getData();
		} else if (message instanceof HandshakeResponse) {
			HandshakeResponse response = (HandshakeResponse) message;
			resultBuffer = response.getResponse();
		} else {
			throw new Exception("message not a websocket type");
		}
		out.write(resultBuffer);
	}

	// Encode the in buffer according to the Section 5.2. RFC 6455
	private IoBuffer encodeOutgoingData(IoBuffer buf) {
		IoBuffer buffer = IoBuffer.allocate(buf.limit() + 2, false);
		buffer.setAutoExpand(true);
		buffer.put((byte) 0x82);
		if (buffer.capacity() <= 125) {
			byte capacity = (byte) (buf.limit());
			buffer.put(capacity);
		} else if (buffer.capacity() == 126) {
			buffer.put((byte) 126);
			buffer.putShort((short) buf.limit());
		} else {
			buffer.put((byte) 127);
			buffer.putLong((int) buf.limit());
		}
		buffer.put(buf);
		buffer.flip();
		return buffer;
	}

}
