package org.red5.net.websocket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.transport.socket.SocketAcceptor;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioProcessor;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * WebSocketTransport
 * <pre>
 * this class will be instanced in red5.xml(or other xml files).
 * will make port listen...
 * </pre>
 * 
 * @author Toda Takahiko
 * @author Paul Gregoire
 */
public class WebSocketTransport implements InitializingBean, DisposableBean {
	
	private static final Logger log = LoggerFactory.getLogger(WebSocketTransport.class);

	private int sendBufferSize = 2048;

	private int receiveBufferSize = 2048;

	private int connectionThreads = 8;

	private int ioThreads = 16;

	private int port = 80;

	private Set<String> addresses = new HashSet<String>();

	private IoHandlerAdapter ioHandler;

	private SocketAcceptor acceptor;

	/**
	 * start to listen ports;
	 * @throws IOException 
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		// instance the websocket handler
		ioHandler = new WebSocketHandler();
		acceptor = new NioSocketAcceptor(Executors.newFixedThreadPool(connectionThreads), new NioProcessor(Executors.newFixedThreadPool(ioThreads)));
		acceptor.setHandler(ioHandler);
		SocketSessionConfig sessionConf = acceptor.getSessionConfig();
		sessionConf.setReuseAddress(true);
		sessionConf.setReceiveBufferSize(receiveBufferSize);
		sessionConf.setSendBufferSize(sendBufferSize);
		acceptor.setReuseAddress(true);
		if (addresses.isEmpty()) {
			acceptor.bind(new InetSocketAddress(port));
		} else {
			try {
				// loop through the addresses and bind
				Set<InetSocketAddress> socketAddresses = new HashSet<InetSocketAddress>();
				for (String addr : addresses) {
					if (addr.indexOf(':') != -1) {
						String[] parts = addr.split(":");
						socketAddresses.add(new InetSocketAddress(parts[0], Integer.valueOf(parts[1])));
					} else {
						socketAddresses.add(new InetSocketAddress(addr, port));
					}
				}
				log.debug("Binding to {}", socketAddresses.toString());
				acceptor.bind(socketAddresses);
			} catch (Exception e) {
				log.error("Exception occurred during resolve / bind", e);
			}			
		}
		log.info("started websocket transport");
	}

	/**
	 * stop to listen ports;
	 */
	@Override
	public void destroy() throws Exception {
		log.info("stop web socket");
		acceptor.unbind();
	}	
	
	public void setAddresses(List<String> addrs) {
		for (String addr : addrs) {
			addresses.add(addr);
		}
		log.info("WebSocket will be bound to {}", addresses);
	}

	/**
	 * @param port the port to set
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * @param sendBufferSize the sendBufferSize to set
	 */
	public void setSendBufferSize(int sendBufferSize) {
		this.sendBufferSize = sendBufferSize;
	}

	/**
	 * @param receiveBufferSize the receiveBufferSize to set
	 */
	public void setReceiveBufferSize(int receiveBufferSize) {
		this.receiveBufferSize = receiveBufferSize;
	}

	/**
	 * @param connectionThreads the connectionThreads to set
	 */
	public void setConnectionThreads(int connectionThreads) {
		this.connectionThreads = connectionThreads;
	}

	/**
	 * @param ioThreads the ioThreads to set
	 */
	public void setIoThreads(int ioThreads) {
		this.ioThreads = ioThreads;
	}
	
}
