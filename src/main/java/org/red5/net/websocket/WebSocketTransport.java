/*
 * RED5 Open Source Flash Server - https://github.com/red5
 * 
 * Copyright 2006-2015 by respective authors (see below). All rights reserved.
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

package org.red5.net.websocket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.mina.core.filterchain.DefaultIoFilterChainBuilder;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.logging.LoggingFilter;
import org.apache.mina.filter.ssl.SslFilter;
import org.apache.mina.transport.socket.SocketAcceptor;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.red5.net.websocket.codec.WebSocketCodecFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * WebSocketTransport
 * 
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

    @SuppressWarnings("unused")
    private int connectionThreads = 8;

    private int ioThreads = 16;

    private int port = 80;

    private Set<String> addresses = new HashSet<String>();

    private IoHandlerAdapter ioHandler;

    private SocketAcceptor acceptor;

    private SecureWebSocketConfiguration secureConfig;

    /**
     * Creates the i/o handler and nio acceptor; ports and addresses are bound.
     * 
     * @throws IOException
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        // create the nio acceptor
        //acceptor = new NioSocketAcceptor(Executors.newFixedThreadPool(connectionThreads), new NioProcessor(Executors.newFixedThreadPool(ioThreads)));
        acceptor = new NioSocketAcceptor(ioThreads);
        // instance the websocket handler
        if (ioHandler == null) {
            ioHandler = new WebSocketHandler();
        }
        log.trace("I/O handler: {}", ioHandler);
        DefaultIoFilterChainBuilder chain = acceptor.getFilterChain();
        // if handling wss init the config
        if (secureConfig != null) {
            SslFilter sslFilter = secureConfig.getSslFilter();
            chain.addFirst("sslFilter", sslFilter);
        }
        if (log.isTraceEnabled()) {
            chain.addLast("logger", new LoggingFilter());
        }
        // add the websocket codec factory
        chain.addLast("protocol", new ProtocolCodecFilter(new WebSocketCodecFactory()));
        // close sessions when the acceptor is stopped
        acceptor.setCloseOnDeactivation(true);
        acceptor.setHandler(ioHandler);
        // requested maximum length of the queue of incoming connections
        acceptor.setBacklog(64);
        SocketSessionConfig sessionConf = acceptor.getSessionConfig();
        sessionConf.setReuseAddress(true);
        sessionConf.setTcpNoDelay(true);
        sessionConf.setReceiveBufferSize(receiveBufferSize);
        sessionConf.setSendBufferSize(sendBufferSize);
        acceptor.setReuseAddress(true);
        if (addresses.isEmpty()) {
            if (secureConfig != null) {
                log.info("WebSocket (wss) will be bound to port {}", port);
            } else {
                log.info("WebSocket (ws) will be bound to port {}", port);
            }
            acceptor.bind(new InetSocketAddress(port));
        } else {
            if (secureConfig != null) {
                log.info("WebSocket (wss) will be bound to {}", addresses);
            } else {
                log.info("WebSocket (ws) will be bound to {}", addresses);
            }
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
        log.info("started {} websocket transport", (isSecure() ? "secure" : ""));
    }

    /**
     * Ports and addresses are unbound (stop listening).
     */
    @Override
    public void destroy() throws Exception {
        log.info("stopped {} websocket transport", (isSecure() ? "secure" : ""));
        acceptor.unbind();
    }

    public void setAddresses(List<String> addrs) {
        for (String addr : addrs) {
            addresses.add(addr);
        }
    }

    /**
     * @param port
     *            the port to set
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * @param sendBufferSize
     *            the sendBufferSize to set
     */
    public void setSendBufferSize(int sendBufferSize) {
        this.sendBufferSize = sendBufferSize;
    }

    /**
     * @param receiveBufferSize
     *            the receiveBufferSize to set
     */
    public void setReceiveBufferSize(int receiveBufferSize) {
        this.receiveBufferSize = receiveBufferSize;
    }

    /**
     * @param connectionThreads
     *            the connectionThreads to set
     */
    public void setConnectionThreads(int connectionThreads) {
        this.connectionThreads = connectionThreads;
    }

    /**
     * @param ioThreads
     *            the ioThreads to set
     */
    public void setIoThreads(int ioThreads) {
        this.ioThreads = ioThreads;
    }

    public boolean isSecure() {
        return secureConfig != null;
    }

    public void setIoHandler(IoHandlerAdapter ioHandler) {
        this.ioHandler = ioHandler;
    }

    public void setSecureConfig(SecureWebSocketConfiguration secureConfig) {
        this.secureConfig = secureConfig;
    }

}
