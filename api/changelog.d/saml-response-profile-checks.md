### Security: SAML sign-in checks more of the Web Browser SSO profile

- A SAML assertion must carry an audience restriction, and every audience restriction must name this service provider. Before, an assertion with no restriction, or with one restriction for this service among others, was accepted.
- Every subject confirmation must use the bearer method, and an assertion issued more than three minutes in the future is refused.
- Authentication and attribute statements outside the SAML assertion namespace are refused, as are a namespace prefix declared for two different namespaces and a document type declaration anywhere in the response.
- A request-tracking cookie with an empty AuthnRequest ID no longer matches a response that answers no request.
- **Upgrade note:** none expected. Identity providers that follow the SAML Web Browser SSO profile send all of this already; a refused sign-in is logged with its reason.
