A module for handling JSON Web Tokens in eXist-db

see http://en.wikipedia.org/wiki/JSON_Web_Token

Provides a single library function:

```xquery
declare module namespace jwt = 'http://max.terpstra.ca/ns/exist-jwt';
declare function jwt:get-verfied-claims(
	$jwt as xs:string,
	$key-callback as function(xs:string) as xs:string*,
	$audience as xs:string?
) as map(xs:string, item()*) external;
```

The `$key-callback` will be called with the token's issuer ID and should return
a sequence of JSON Web Key values that may be used to verify the signature.

The return value is the JWT payload (aka "claims") translated into native
XQuery data types. Objects are represented as `map(xs:string, item()*)`, arrays
as sequences, true/false as `xs:boolean`, strings as `xs:string`, and numbers as
`xs:decimal`.
