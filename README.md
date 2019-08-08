# irule-detector

One of F-Secure’s researchers (Christoffer Jerkeby - https://www.linkedin.com/in/jerkeby/) has discovered an exploitable security flaw that is present in some implementations of F5 Networks’ popular BigIP load balancer. The class of security flaw is often referred to as a Remote Code or Command Execution (RCE) vulnerability. The vulnerability when exploited permits an attacker to execute commands on the technology to affect a compromise.

The issue has been disclosed to the vendor and their advisory note can be found here - https://support.f5.com/csp/article/K15650046.

F-Secure's Christoffer Jerkeby - https://www.linkedin.com/in/jerkeby/ has developed a Burp Proxy (https://portswigger.net/burp) extension to identify the presence of the vulnerability.

The security issue is present in the product’s iRule feature. iRule is a powerful and flexible feature within the BigIp local traffic management (LTM) system that is used to manage network traffic. iRules are created using the Tool Command Language (Tcl). Certain coding practices may allow an attacker to inject arbitrary Tcl commands, which could be executed in the security context of the target Tcl script.

The coding flaw and class of vulnerability is not new and has been known, along with other command injection vulnerabilities in other popular languages for some time (https://wiki.tcl-lang.org/page/Injection+Attack). 

The language used for defining F5 iRules is a fork of TCL-8.4. The design of the language allows for substitutions in statements and commands and this feature of Tcl can allow injection attacks similar to those seen in SQL or shell scripting languages, where arbitrary user input is interpreted as code and executed. Some iRules parse data from incoming web requests, and incorrectly interpret that data as commands to execute.

<example>
Payload: [HTTP::respond 666 {vuln}]

URL Encoded Payload: %5BHTTP%3A%3Arespond%20666%20%7Bvuln%7D%5D

$ curl -I --cookie cookie=%5BHTTP%3A%3Arespond%20666%20%7Bvuln%7D%5D https://www.host.com/index.aspx | grep vuln

$ curl -I -H RequestHeader=%5BHTTP%3A%3Arespond%20666%20%7Bvuln%7D%5D https://www.host.com/index.aspx | grep vuln
</example>

F-Secure have also contributed to the development of two publicly available open source tools that can analyse Tcl scripts in an effort to help identify if they are vulnerable to command injection flaws. TestTcl is a library for unit testing BIG-IP iRules and Tclscan is a tool that (lexically) scans Tcl code specifically for command injection flaws:

- Tcl scan https://github.com/kugg/tclscan
- TestTcl: https://github.com/landro/testcl

Any Tcl scripts found to be vulnerable can be modified to eradicate the flaw using the guidance found at these resources:

- https://wiki.tcl-lang.org/page/double+substitution
- https://wiki.tcl-lang.org/page/Brace+your+expr-essions
- https://wiki.tcl-lang.org/page/Static+syntax+analysis

Sometimes the presence of an F5 BigIP can be determined in its responses to non-existent content and/or when it sets application cookies in web responses; as can be seen below:

<example>
$ curl -I https://www.host.com/302

>HTTP/2 302
..
>Server: BigIp
..
</example>

<example>
$ curl -I https://www.host.com/302

>HTTP/2 302
..
>set-cookie: BIGip[ .. ]; path=/
..
</example>
