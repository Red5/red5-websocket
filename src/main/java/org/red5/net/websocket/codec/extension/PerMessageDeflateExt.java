package org.red5.net.websocket.codec.extension;

/**
 * Extension to WebSocket which provides per-message deflate.
 * 
 * @see <a href="http://tools.ietf.org/html/draft-ietf-hybi-permessage-compression-18">IETF Draft</a>
 * @see <a href="https://www.igvita.com/2013/11/27/configuring-and-optimizing-websocket-compression/">Configuration and optimization</a>
 * 
 * @author Paul Gregoire
 */
public class PerMessageDeflateExt implements WebSocketExtension {

	private static final String id = "permessage-deflate";

	/** {@inheritDoc} */
	public String getId() {
		return id;
	}
	
}
