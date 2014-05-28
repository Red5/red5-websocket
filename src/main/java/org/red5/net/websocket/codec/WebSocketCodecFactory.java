package org.red5.net.websocket.codec;

import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolEncoder;

public class WebSocketCodecFactory implements ProtocolCodecFactory {
	
	private final ProtocolEncoder encoder;

	private final ProtocolDecoder decoder;

	public WebSocketCodecFactory() {
		encoder = new WebSocketEncoder();
		decoder = new WebSocketDecoder();
	}

	@Override
	public ProtocolDecoder getDecoder(IoSession arg0) throws Exception {
		return decoder;
	}

	@Override
	public ProtocolEncoder getEncoder(IoSession arg0) throws Exception {
		return encoder;
	}

}
