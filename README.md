# jsqrl-server
JSQRL Server: Java web server implementation of the SQRL authentication protocol.



This library can be used to process SQRL authentication requests. It currently follows (most of) the protocol outlined on GRC.com: https://www.grc.com/sqrl/semantics.htm


This project has no framework requirements (you could even get away with not using JavaEE if you wanted). 
The only requirement of your server is that it needs to accept an HTTP POST from a SQRL client.

For an implementation example, see my [Spring Boot with Spring Security example](https://github.com/banichols/jsqrl-spring-boot-example), which is currently deployed to https://demo.jsqrl.org

## Getting Started

There are a few important classes that you will need to implement.

* `org.jsqrl.model.SqrlUser`: This interface should be implemented by whichever type of user you want to authenticate using SQRL.
* `org.jsqrl.service.SqrlUserService` : This interface should be implemented by the service you use to interface with your user objects.
* `org.jsqrl.service.SqrlAuthenticationService` : This interface should be implemented by the service you use to handle your authentication data.

And then there are a few classes you will need to instantiate.
* `org.jsqrl.config.SqrlConfig` : This is the object that will allow you to configure various SQRL related variables such as your Server Friendly Name, Nut token expiration, and the URI the SQRL client should use for its HTTP POSTs.
* `org.jsqrl.service.SqrlNutService` : This is the service that will generate your SQRL Nut tokens. It requires the configuration object defined above and all the aspects that are required to create SQRL nuts - a random number generator (such as SecureRandom), a hashing instance, and an encryption key.
* `org.jsqrl.server.JSqrlServer` : This is the main server class that handles the SQRL protocol. It just needs to be instantiated with your SqrlUserService, SqrlAuthenticationService, SqrlConfig, and SqrlNutService.

Once you have those six things taken care of you are ready to start taking SQRL requests.
* A user will need a way to request a SQRL nut, in which case you will call `JSqrlServer.createAuthenticationRequest`. Ideally you would have some HTTP GET or similar type of request to provide a user with one of these.
* Any request that comes in via the HTTP POST should be passed to `JSqrlServer.handleClientRequest`
* There will need to be a way that the user can query if their originally provided Nut has been authenticated. Ideally you would have the front-end constantly make this query and refresh the page once the server has verified that the nut has been authenticated.

Notes:
* This library does not generate the QR code itself. There are front-end libraries that will provide this functionality, but if you want to do it server-side there are Java library options for that as well. I used [qrcode.js](https://davidshimjs.github.io/qrcodejs/) in my [Spring Boot example](https://github.com/banichols/jsqrl-spring-boot-example)
* While this library currently supports core SQRL functionality, there are a few missing features (such as ask).
* I still have a lot of polishing work to do on this library. 

For more information on SQRL, please visit https://www.grc.com/sqrl/sqrl.htm . Many thanks to Steve Gibson and GRC for all the work on creating this exciting new authentication protocol!
