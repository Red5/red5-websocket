package org.red5.net.websocket;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Set;

import org.apache.mina.core.buffer.IoBuffer;

public class WebSocketScope {

	private String charsetName = "UTF8"; //"SJIS";
	
	private String path;

	private Set<WebSocketConnection> conns = new HashSet<WebSocketConnection>();

	private Set<IWebSocketDataListener> listeners = new HashSet<IWebSocketDataListener>();

	/**
	 * constructor
	 * @param path path data
	 */
	public WebSocketScope(String path) {
		this.path = path; // /room/name
	}

	/**
	 * get the set of connections
	 * @return the conns
	 */
	public Set<WebSocketConnection> getConns() {
		return conns;
	}

	/**
	 * get the path info of scope
	 * @return path data.
	 */
	public String getPath() {
		return path;
	}

	/**
	 * add new connection on scope
	 * @param conn WebSocketConnection
	 */
	public void addConnection(WebSocketConnection conn) {
		conns.add(conn);
		for (IWebSocketDataListener listener : listeners) {
			listener.connect(conn);
		}
	}

	/**
	 * remove connection from scope
	 * @param conn WebSocketConnection
	 */
	public void removeConnection(WebSocketConnection conn) {
		conns.remove(conn);
		for (IWebSocketDataListener listener : listeners) {
			listener.leave(conn);
		}
	}

	/**
	 * add new listener on scope
	 * @param listener IWebSocketDataListener
	 */
	public void addListener(IWebSocketDataListener listener) {
		listeners.add(listener);
	}

	/**
	 * remove listener from scope
	 * @param listener IWebSocketDataListener
	 */
	public void removeListener(IWebSocketDataListener listener) {
		System.out.println("remove:" + listener.getPath());
		listeners.remove(listener);
	}

	/**
	 * check the scope state.
	 * @return true:still have relation
	 */
	public boolean isValid() {
		return (conns.size() + listeners.size()) > 0;
	}

	/**
	 * get the message from client
	 */
	public void setMessage(IoBuffer buffer) {
		for (IWebSocketDataListener listener : listeners) {
			try {
				listener.getData(buffer);
				listener.getMessage(getData(buffer));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			} catch (WebSocketException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * cut off first 0x00 and last 0xFF
	 * @param buffer input buffer data
	 * @return String data from client
	 * @throws UnsupportedEncodingException 
	 * @throws WebSocketException when we get invalid input.
	 */
	private String getData(IoBuffer buffer) throws WebSocketException, UnsupportedEncodingException {
		byte[] b = new byte[buffer.capacity()];
		int i = 0;
		for (byte bi : buffer.array()) {
			i++;
			if (i == 1) {
				if (bi == 0x00) {
					continue;
				} else {
					throw new WebSocketException("first byte must be 0x00 for websocket");
				}
			}
			if (bi == (byte) 0xFF) {
				break;
			}
			b[i - 2] = bi;
		}
		return new String(b, charsetName).trim();
	}

	public String getCharsetName() {
		return charsetName;
	}

	public void setCharsetName(String charsetName) {
		this.charsetName = charsetName;
	}
}
