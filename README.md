red5-websocket
==============

Websocket plug-in for Red5

Thanks to Takahiko Toda (poepoemix@hotmail.com) for the initial code that we started with.

Configuration
--------------

Add the WebSocket transport to the jee-container.xml or red5.xml. If placing it in the red5.xml, ensure the bean comes after the plugin launcher entry.

To bind to one or many IP addresses and ports:
```
<bean id="webSocketTransport" class="org.red5.net.websocket.WebSocketTransport">
        <property name="addresses">
            <list>
            	<value>192.168.1.174</value>
            	<value>192.168.1.174:8080</value>
            	<value>192.168.1.174:10080</value>
            </list>
        </property>
</bean>
```

If you don't want to specify the IP to bind to:
```
<bean id="webSocketTransport" class="org.red5.net.websocket.WebSocketTransport">
	<property name="port" value="8080"/>
</bean>

```

Adding WebSocket to an Application
------------------------

To enable websocket support in your application, add this to your appStart() method:

```
  WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
  manager.addApplication(scope.getName());
```

For clean-up add this to appStop():

```
  WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
  manager.removeApplication(scope.getName());
```
