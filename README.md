red5-websocket
==============

Websocket plug-in for Red5

This plugin is meant to provide websocket access to applications running in red5. Special thanks to Takahiko Toda (poepoemix@hotmail.com) for the initial code that we started with. The latest code has a rewritten handshake routine which compiles with rfc6455.

http://tools.ietf.org/html/rfc6455

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

If you don't want to specify the IP:
```
<bean id="webSocketTransport" class="org.red5.net.websocket.WebSocketTransport">
	<property name="port" value="8080"/>
</bean>

```
To support secure communication (wss) add this:

```
    <bean id="webSocketTransportSecure" class="org.red5.net.websocket.WebSocketTransport">
        <property name="secureConfig">
            <bean id="webSocketSecureConfig" class="org.red5.net.websocket.SecureWebSocketConfiguration">
                <property name="keystoreType" value="JKS"/>
                <property name="keystoreFile" value="conf/keystore"/>
                <property name="keystorePassword" value="password"/>
                <property name="truststoreFile" value="conf/truststore"/>
                <property name="truststorePassword" value="password"/>
            </bean>
        </property>
        <property name="addresses">
            <list>
                <value>192.168.1.174:10081</value>
            </list>
        </property>
    </bean>
```

Adding WebSocket to an Application
------------------------

To enable websocket support in your application, add this to your appStart() method:

```
  WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
  manager.addApplication(scope);
```

For clean-up add this to appStop():

```
  WebSocketScopeManager manager = ((WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin")).getManager();
  manager.removeApplication(scope);
```

Test Page
-------------------

Replace the wsUri variable with your applications path.

```
<!DOCTYPE html>  
<meta charset="utf-8" />  
<title>WebSocket Test</title>  
<script language="javascript" type="text/javascript">  
var wsUri = "ws://192.168.1.174:10080/myapp"; 
var output;  function init() { output = document.getElementById("output"); testWebSocket(); }  function testWebSocket() { websocket = new WebSocket(wsUri); websocket.onopen = function(evt) { onOpen(evt) }; websocket.onclose = function(evt) { onClose(evt) }; websocket.onmessage = function(evt) { onMessage(evt) }; websocket.onerror = function(evt) { onError(evt) }; }  function onOpen(evt) { writeToScreen("CONNECTED"); doSend("WebSocket rocks"); }  function onClose(evt) { writeToScreen("DISCONNECTED"); }  function onMessage(evt) { writeToScreen('<span style="color: blue;">RESPONSE: ' + evt.data+'</span>'); websocket.close(); }  function onError(evt) { writeToScreen('<span style="color: red;">ERROR:</span> ' + evt.data); }  function doSend(message) { writeToScreen("SENT: " + message);  websocket.send(message); }  function writeToScreen(message) { var pre = document.createElement("p"); pre.style.wordWrap = "break-word"; pre.innerHTML = message; output.appendChild(pre); }  window.addEventListener("load", init, false);  </script>  <h2>WebSocket Test</h2> <div id="output"></div>
```

