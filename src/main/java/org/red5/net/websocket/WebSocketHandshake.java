package org.red5.net.websocket;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.mina.core.buffer.IoBuffer;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.red5.server.plugin.PluginRegistry;

/**
 * WebSocketHandshake
 * <pre>
 * This class handles the handshake process. WebSocket version 13 is required.
 * </pre>
 * @see <a href="https://developer.mozilla.org/en-US/docs/WebSockets/Writing_WebSocket_servers">Mozilla - Writing WebSocket Servers</a>
 *  
 * @author Paul Gregoire
 */
public class WebSocketHandshake {

	private static final Logger log = LoggerFactory.getLogger(WebSocketHandshake.class);

	// concatenate this with the clients key
	private static final String WEBSOCKET_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	
	private static final byte[] CRLF = { 0x0D, 0x0A };
	
	private WebSocketConnection conn;

	// clients key
	private String key;

	private String origin;

	private String host;

	private String path;

	WebSocketHandshake() {
		
	}
	
	/**
	 * constructor with connection object.
	 * @param conn connection object.
	 */
	public WebSocketHandshake(WebSocketConnection conn) {
		this.conn = conn;
	}

	/**
	 * handShake
	 * <pre>
	 * analyze handshake input from client.
	 * </pre>
	 * @param buffer ioBuffer
	 */
	public void handShake(IoBuffer buffer) throws WebSocketException {
		byte[] b = new byte[buffer.capacity()];
		String data;
		int i = 0;
		for (byte bi : buffer.array()) {
			if (bi == 0x0D || bi == 0x0A) {
				if (b.length != 0) {
					data = (new String(b)).trim();
					if (data.contains("GET ")) {
						// get the path data for handShake
						String[] ary = data.split("GET ");
						ary = ary[1].split(" HTTP/1.1");
						path = ary[0];
						conn.setPath(ary[0]);
						ary = ary[0].split("/");
						WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
						if (ary.length <= 1 || !manager.isEnabled(ary[1])) {
							// scope is not application. handshake will be false;
							// send disconnect message
							IoBuffer buf = IoBuffer.allocate(4);
							buf.put(new byte[] { (byte) 0xFF, (byte) 0x00 });
							buf.flip();
							conn.send(buf);
							// close connection
							conn.close();
							throw new WebSocketException("Handshaking failed");
						}
					} else if (data.contains("Sec-WebSocket-Key")) {
						// get the key data
						key = data.substring(data.indexOf(':') + 2);
					} else if (data.contains("Sec-WebSocket-Version")) {
						// check the version
						if (data.indexOf("13") == -1) {
							log.info("Version 13 was not found in the request, handshaking may fail");
						}
					} else if (data.contains("Host")) {
						// get the host data
						String[] ary = data.split("Host: ");
						host = ary[1];
						conn.setHost(ary[1]);
					} else if (data.contains("Origin")) {
						// get the origin data
						String[] ary = data.split("Origin: ");
						origin = ary[1];
						conn.setOrigin(ary[1]);
					}
					// for the information print out the string data
					if (data.length() > 4) {
						log.debug(data);
					}
				}
				i = 0;
				b = new byte[buffer.capacity()];
			} else {
				b[i] = bi;
				i++;
			}
		}
		// start the handshake reply
		doHandShake();
	}

	/**
	 * start the handshake reply
	 * @param key3
	 */
	private void doHandShake() throws WebSocketException {
		if (key == null) {
			throw new WebSocketException("Key data is missing");
		}
		byte[] accept;
		try {
			// concatenate the key and magic string, then SHA1 hash and base64 encode
			accept = crypt(key + WEBSOCKET_MAGIC_STRING);
		} catch (NoSuchAlgorithmException e) {
			throw new WebSocketException("Algorithm is missing");
		}
		// make up reply data...
		IoBuffer buf = IoBuffer.allocate(2048);
		buf.put("HTTP/1.1 101 Switching Protocols".getBytes());
		buf.put(CRLF);
		buf.put("Upgrade: websocket".getBytes());
		buf.put(CRLF);
		buf.put("Connection: Upgrade".getBytes());
		buf.put(CRLF);
		buf.put(("Sec-WebSocket-Origin: " + origin).getBytes());
		buf.put(CRLF);
		buf.put(String.format("Sec-WebSocket-Location: ws://%s%s", host, path).getBytes());
		buf.put(CRLF);
		buf.put(String.format("Sec-WebSocket-Accept: %s", new String(accept)).getBytes());
		buf.put(CRLF);
		buf.put(CRLF);
		buf.put(accept);
		buf.flip();
		// write the data on session
		conn.getSession().write(buf);
		// handshake is finished
		conn.setConnected();
		WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
		manager.addConnection(conn);
		log.debug("Handshake complete");
	}

	/**
	 * Perform the accept creation routine from RFC6455.
	 * @see <a href="http://tools.ietf.org/html/rfc6455">RFC6455</a>
	 * 
	 * @param in input data
	 * @return crypted data
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] crypt(String in) throws NoSuchAlgorithmException {
		log.debug("Crypt: >{}<", in);
		if (in == null || in.length() == 0) {
			throw new IllegalArgumentException("Missing body for accept calculation");
		}
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] crypted = Base64.encode(md.digest(in.getBytes()));
		return crypted;
	}
	
	public static void main(String[] args) throws Exception {
		WebSocketHandshake hs = new WebSocketHandshake();
		if ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".equals(new String(hs.crypt("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))) {
			System.out.println("Accept routine is valid");
		} else {
			System.err.println("Accept routine is invalid!");
		}
	}
	
}
