package org.red5.net.websocket;

import org.red5.server.Server;
import org.red5.server.adapter.MultiThreadedApplicationAdapter;
import org.red5.server.plugin.Red5Plugin;

/**
 * WebSocketPlugin
 * <pre>
 * This program will be called by red5 PluginLauncher
 * and hold the application Context or Application Adapter
 * </pre>
 * @author Toda Takahiko
 */
public class WebSocketPlugin extends Red5Plugin {

	public WebSocketPlugin() {
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doStart() throws Exception {
		super.doStart();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return "WebSocketPlugin";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Server getServer() {
		return super.getServer();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setApplication(MultiThreadedApplicationAdapter application) {
		WebSocketScopeManager manager = new WebSocketScopeManager();
		manager.addPluginedApplication(application.getName());
		super.setApplication(application);
	}
}
