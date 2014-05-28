package org.red5.net.websocket;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebSocketHandler
 * <pre>
 * IoHandlerAdapter for webSocket
 * </pre>
 * @author Toda Takahiko
 */
public class WebSocketHandler extends IoHandlerAdapter {

	private static final Logger log = LoggerFactory.getLogger(WebSocketHandler.class);

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
		log.error("exception", cause);
		super.exceptionCaught(session, cause);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void sessionCreated(IoSession session) throws Exception {
		session.setAttribute("connection", new WebSocketConnection(session));
		super.sessionCreated(session);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void sessionClosed(IoSession session) throws Exception {
		// remove connection from scope.
		WebSocketConnection conn = (WebSocketConnection) session.getAttribute("connection");
		conn.close();
		super.sessionClosed(session);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void messageReceived(IoSession session, Object message) throws Exception {
		if (message instanceof IoBuffer) {
			WebSocketConnection conn = (WebSocketConnection) session.getAttribute("connection");
			conn.receive((IoBuffer) message);
		}
		super.messageReceived(session, message);
	}
}
