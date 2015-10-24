package org.red5.net.websocket.model;

import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;

import org.apache.mina.core.buffer.IoBuffer;
import org.red5.net.websocket.WebSocketConnection;

/**
 * Represents incoming WebSocket data which has been decoded.
 * 
 * @author Paul Gregoire (mondain@gmail.com)
 */
public class WSMessage {

	// message type
	private MessageType messageType;

	// the originating connection for this message
	private WeakReference<WebSocketConnection> connection;
	
	// payload
	private IoBuffer payload;
	
	// the path on which this message originated
	private String path;
	
	// creation time
	private long timeStamp = System.currentTimeMillis();

	/**
	 * Returns the payload data as a UTF8 string.
	 * 
	 * @return string
	 * @throws UnsupportedEncodingException
	 */
	public String getMessageAsString() throws UnsupportedEncodingException {
		return new String(payload.array(), 0, payload.limit(), "UTF8");
	}
	
	public MessageType getMessageType() {
		return messageType;
	}

	public void setMessageType(MessageType messageType) {
		this.messageType = messageType;
	}

	public WebSocketConnection getConnection() {
		return connection.get();
	}

	public void setConnection(WebSocketConnection connection) {
		this.connection = new WeakReference<WebSocketConnection>(connection);
		// set the connections path on the message
		setPath(connection.getPath());
	}

	/**
	 * Returns the payload.
	 * 
	 * @return payload
	 */
	public IoBuffer getPayload() {
		return payload.flip();
	}

	public void setPayload(IoBuffer payload) {
		this.payload = payload;
	}
	
	/**
	 * Adds additional payload data.
	 * 
	 * @param additionalPayload
	 */
	public void addPayload(IoBuffer additionalPayload) {
		if (payload == null) {
			payload = IoBuffer.allocate(additionalPayload.limit());
			payload.setAutoExpand(true);
		}
		this.payload.put(additionalPayload);
	}
	
	/**
	 * Adds additional payload data.
	 * 
	 * @param additionalPayload
	 */
	public void addPayload(byte[] additionalPayload) {
		if (payload == null) {
			payload = IoBuffer.allocate(additionalPayload.length);
			payload.setAutoExpand(true);
		}
		this.payload.put(additionalPayload);
	}	
	
	public boolean isPayloadComplete() {
		return !payload.hasRemaining();
	}

	public long getTimeStamp() {
		return timeStamp;
	}

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

	@Override
	public String toString() {
		return "WSMessage [messageType=" + messageType + ", timeStamp=" + timeStamp + ", path=" + path + ", payload=" + payload + "]";
	}
	
}
