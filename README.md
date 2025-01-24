# How to get a JWT via Postman

In Postman go set up a GET request to `{{host}}/api/v1/beer`. Navigate to the Authorization tab and change the Auth Type to "OAuth 2.0".
- Make sure to choose the "Add authorization data to" property to "Request Headers".
- Scroll down to "Configure New Token" and set the token name to "new-token".
- -Access Token URL should be `http://localhost:9000/oauth2/token`. The port is set in `application.properties`.
- Select  "Client Credentials" as the Grant type. This is used for service to service communication.
- Enter "messaging-client" as the Client ID. Note that this is configured in the `SecurityConfig.registeredClientRepository()` method.
- Enter "secret" as the Client Secret. Note that this is configured in the `SecurityConfig.registeredClientRepository()` method. The `{noop}` falls away. Why? Its briefly discussed [in this tutorial](https://www.udemy.com/course/spring-framework-6-beginner-to-guru/learn/lecture/35624634#questions).
- Enter `message.read message.write` as the Scope. Note that this is configured in the `SecurityConfig.registeredClientRepository()` method. The `{noop}` falls away. Why? Its briefly discussed [in this tutorial](https://www.udemy.com/course/spring-framework-6-beginner-to-guru/learn/lecture/35624634#questions).
- Click "Get New Access Token".
- If successfull, Postman will present you with a client token.

Move over to Chrome and navigate to a [JWT decoder](https://jwt.ms/) and enter the JWT to view the information. 

Postman will also store the token you've just generated in the "Available Tokens" under the Current Token.






















