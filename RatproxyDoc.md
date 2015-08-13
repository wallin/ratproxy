# ratproxy - passive web application security assessment tool #

  * Written and maintained by [Michal Zalewski](http://lcamtuf.coredump.cx/) <[lcamtuf@google.com](mailto:lcamtuf@google.com)>.
  * Copyright 2007, 2008 Google Inc, rights reserved.
  * Released under terms and conditions of the Apache License, version 2.0.

## What is ratproxy? ##

_Ratproxy_ is a semi-automated, largely passive web application security audit tool. It is meant to complement active crawlers and manual proxies more commonly used for this task, and is optimized specifically for an accurate and sensitive detection, and automatic annotation, of potential problems and security-relevant design patterns based on the observation of existing, user-initiated traffic in complex _web 2.0_ environments. The approach taken with _ratproxy_ offers several important advantages over more traditional methods:

  * **No risk of disruptions.** In the default operating mode, tool does not generate a high volume of attack-simulating traffic, and as such may be safely employed against production systems at will, for all types of ad hoc, post-release audits. Active scanners may trigger DoS conditions or persistent XSSes, and hence are poorly suited for live platforms.

  * **Low effort, high yield.** Compared to active scanners or fully manual proxy-based testing, _ratproxy_ assessments take very little time or bandwidth to run, and proceed in an intuitive, distraction-free manner - yet provide a good insight into the inner workings of a product, and the potential security vulnerabilities therein. They also afford a consistent and predictable coverage of user-accessible features.

  * **Preserved control flow of human interaction.** By silently following the browser, the coverage in locations protected by nonces, during other operations valid only under certain circumstances, or during dynamic events such as cross-domain `Referer` data disclosure, is greatly enhanced. Brute-force crawlers and fuzzers usually have no way to explore these areas in a reliable manner.

  * **WYSIWYG data on script behavior.** Javascript interfaces and event handlers are explored precisely to a degree they are used in the browser, with no need for complex guesswork or simulations. Active scanners often have a significant difficulty exploring JSON responses, `XMLHttpRequest()` behavior, UI-triggered event data flow, and the like.

  * **Easy process integration.** The proxy can be transparently integrated into an existing manual security testing or interface QA processes without introducing a significant setup or operator training overhead.

## Is it worth trying out? ##

There are numerous alternative proxy tools meant to aid security auditors - most notably [WebScarab](http://www.owasp.org/index.php/Category:OWASP_WebScarab_Project), [Paros](http://www.parosproxy.org/), [Burp](http://portswigger.net/proxy/), [ProxMon](http://www.isecpartners.com/proxmon.html), and
[Pantera](http://www.owasp.org/index.php/Category:OWASP_Pantera_Web_Assessment_Studio_Project). Stick with whatever suits your needs, as long as you get the data you need in the format you like.

That said, _ratproxy_ is there for a reason. It is designed specifically to deliver concise reports that focus on prioritized issues of clear relevance to contemporary _web 2.0_ applications, and to do so in a hands-off, repeatable manner. It should not overwhelm you with raw HTTP traffic dumps, and it goes far beyond simply providing a framework to tamper with the application by hand.

_Ratproxy_ implements a number of fairly advanced and unique checks based on our experience with these applications, as well as all the related browser quirks and content handling oddities. It features a sophisticated content-sniffing functionality capable of distinguishing between stylesheets and Javascript code snippets, supports SSL man-in-the-middle, on the fly Flash ActionScript decompilation, and even offers an option to confirm high-likelihood flaw candidates with very lightweight, a built-in active testing module.

Last but not least, if you are undecided, the proxy may be easily chained with third-party security testing proxies of your choice.

## How does it avoid false positives? ##

Operating in a non-disruptive mode makes the process of discovering security flaws particularly challenging, as the presence of some vulnerabilities must be deduced based on very subtle, not always reliable cues - and even in active testing modes, _ratproxy_ strives to minimize the amount of rogue traffic generated, and side effects caused.

The set of checks implemented by _ratproxy_ is outlined later on - but just as importantly, underneath all the individual check logic, the proxy uses a number of passively or semi-passively gathered signals to more accurately prioritize reported problems and reduce the number of false alarms as much as possible. The five core properties examined for a large number of checks are:

  * What the declared and actually detected MIME type for the document is. This is a fairly important signal, as many problems manifest themselves only in presence of subtle mismatches between these two - whereas other issues need to be treated as higher or lower priority based on this data. More fundamentally, the distinction between certain classes of content - such as "renderables" that may be displayed inline by the browser - is very important to many checks.

  * How pages respond to having cookie-based authentication removed. This provides useful information on whether the resource is likely to contain user-specific data, amongst other things. Carefully preselected requests that fail some security checks are replayed as-is, but with authentication data removed; responses are then compared, with virtually no risk of undesirable side effects in common applications.

  * Whether requests seem to contain non-trivial, sufficiently complex security tokens, or other mechanisms that may make the URL difficult to predict. This provides information needed to determine the presence of XSRF defenses, to detect cross-domain token leakage, and more. (In active testing mode, the function of such tokens is further validated by replaying the request with modified values.)

  * Whether any non-trivial parts of the query are echoed back in the response, and in what context. This is used to pick particularly interesting candidates for XSS testing - or, in active mode, to schedule low-overhead, lightweight probes.

  * Whether the interaction occurs on a boundary of a set of domains defined by runtime settings as the trusted environment subjected to the audit, and the rest of the world. Many boundary behaviors have a special significance, as they outline cross-domain trust patterns and information disclosure routes.

In addition to this, several places employ check-specific logic to further fine-tune the results.

## What specific tests are implemented? ##

Key low-level check groups implemented by _ratproxy_ are:

  * **Potentially unsafe JSON-like responses that may be vulnerable to cross-domain script inclusion.** JSON responses may be included across domains by default, unless safe serialization schemes, security tokens, or parser breaking syntax is used. _Ratproxy_ will check for these properties, and highlight any patterns of concern.

  * **Bad caching headers on sensitive content.** _Ratproxy_ is able to accurately detect presence of several types of sensitive documents, such as locations that return user-specific data, or resources that set new, distinctive cookies. If the associated requests have predictable URLs, and lack HTTP caching directives that would prevent proxy-level caching, there is a risk of data leakage.

> In pedantic mode, _ratproxy_ will also spot differences in `HTTP/1.1` and `HTTP/1.0` caching intents - as these may pose problems for a fraction of users behind legacy cache engines (such as several commercial systems used to date by some corporations).

  * **Suspicious cross-domain trust relationships.** Based on the observation of dynamic control flow, and a flexible definition of trusted perimeter, ratproxy is capable of accurately detecting dangerous interactions between domains, including but not limited to:
    * Security token leakage via `Referer` headers,
    * Untrusted script or stylesheet inclusion,
    * General references to third-party domains,
    * Mixed content issues in HTTPS-only applications,
    * Tricky cross-domain `POST` requests in single sign-on systems.

  * **Numerous classes of content serving issues** - a broad class of problems that lead to subtles XSSes, and includes MIME type mismatches, charset problems, Flash issues, and more. Research indicates that a vast number of seemingly minor irregularities in content type specifications may trigger cross-site scripting in unusal places; for example, subtle mistakes such as serving GIF files as `image/jpeg`, typing `utf8` instead of `utf-8` in `Content-Type` headers, or confusing HTTP charset with XML declaration charset values are all enough to cause trouble. Even seemingly harmless actions such as serving valid, attacker-controlled PNG images inline were known to cause problems due to browser design flaws.

> Likewise, certain syntax patterns are dangerous to return to a browser regardless of MIME types, as there are known methods to have MIME types overridden or ignored altogether. _Ratproxy_ uses a set of fairly advanced checks that spot these problems with a considerable accuracy and relatively few false positives in contemporary scenarios, accounting for various classes of content served.

  * **Queries with insufficient XSRF defenses** (`POST`s, plus any requests that set cookies by default; and other suspicious looking `GET` requests as an option). In active testing mode, the proxy will also actually try to validate XSRF protections by replaying requests with modified token values, and comparing responses.

  * **Suspected or confirmed XSS / data injection vectors**, including attacks through included JSON-based script injection, or response header splitting. In the default, passive mode, _ratproxy_ does not attempt to confirm the quality of XSS filtering in tested applications, but it will automatically enumerate and annotate the best subjects for manual inspection - and will offer the user the ability to feed this data to external programs, or modify and replay interesting requests on the fly. The proxy will also take note of any seemingly successful manual XSS attempts taken by the user.

> In active testing mode, the proxy will go one step further and attempt a single-shot verification of XSS filtering mechanisms, carefully tweaking only these request parameters that truly need to be tested at the time (and carefully preserving XSRF tokens, and more).

  * **HTTP and META redirectors.** Redirectors, unless properly locked down, may be used without owner's content, which in some contexts might be considered undesirable. Furthermore, in extreme cases, poorly implemented redirectors may open up cross-site scripting vectors in less common browsers.

> _Ratproxy_ will take note of any redirectors observed for further testing.

  * **A broad set of other security problems**, such as alarming Javascript, OGNL, Java, SQL statements, file inclusion patterns, directory indexes, server errors, and so forth. _Ratproxy_ will preselect particularly interesting candidates for further testing.

> In the initial beta, not all web technologies may necessarily be analyzed to greatest extent possible. We intend to actively extend and improve the tool based on your feedback, however.

  * Several additional, customizable classes of requests and responses useful in understanding the general security model of the application (file upload forms, `POST` requests, cookie setters, etc).

For a full list of individual issues reported, please see `messages.list` in the source tarball.

## What is the accuracy of reported findings? ##

_Ratproxy_ usually fares very well with typical, rich, modern web applications - that said, by the virtue of operating in passive mode most of the time, all the findings reported merely highlight areas of concern, and are not necessarily indicative of actual security flaws. The information gathered during a testing session should be then interpreted by a security professional with a good understanding of the common problems and security models employed in web applications.

Please keep in mind that the tool is still in beta, and you may run into problems with technologies we had no chance to examine, or that were not a priority at this time. Please contact the author to report any issues encountered.

## How to interpret and address the issues reported? ##

Many of the problems reported by _ratproxy_ are self-explanatory and straightforward to address. Some challenges, however, might require a more in-depth analysis to fully qualify and resolve.

There are several organizations that put a considerable effort into documenting and explaining these problems, and advising the public on how to address them. We encourage you to refer to the materials published by [OWASP](http://www.owasp.org/) and [Web Application Security Consortium](http://www.webappsec.org/projects/articles/), amongst others:

  * [OWASP Engineering principles](http://www.owasp.org/index.php/Category:Principle)
  * [OWASP guidelines](http://www.owasp.org/index.php/Category:OWASP_Guide_Project)
  * [WASC article library](http://www.webappsec.org/projects/articles/)

## How to run the proxy? ##

> **NOTE:** Please do not be evil. Use _ratproxy_ only against services you own, or have a permission to test. Keep in mind that although the proxy is mostly passive and unlikely to cause disruptions, it is not stealth. Furthermore, the proxy is not designed for dealing with rogue and misbehaving HTTP servers and clients - and offers no guarantees of safe (or sane) behavior there.

Initiating _ratproxy_ sessions is fairly straigtforward, once an appropriate set of runtime options is dediced upon. Please familiarize yourself with these settings, as they have a very significant impact on the quality of produced reports.

The main binary, `./ratproxy`, takes the following arguments:

```
  -w logfile    - this option causes raw, machine-readable proxy logs to be written to
                  a specified file. By default, all data is written to stdout only. 
                  The log produced this way is not meant for human  consumption - it
                  might be postprocessed with third-party utilities, or pretty-printed 
                  using 'ratproxy-report.sh', however.

  -v logdir     - prompts ratproxy to store full HTTP traces of all requests featured
                  in the logfile, writing them to a specified directory. In most cases, 
                  it is advisable to enable this option, as it provides useful hints 
                  for further analysis.

  -p port       - causes ratproxy to listen for browser connections on a TCP port
                  different than the default 8080.

  -r            - instructs ratproxy to accept remote connections. By default, the proxy
                  listens on loopback interfaces only. This option enables remote access 
                  to the service.

                  WARNING: Ratproxy does not feature any specific access control 
                  mechanisms, and may be abused if exposed to the Internet. Please make 
                  sure to use proper firewall controls whenever using -r option to 
                  prevent this.

  -d domain     - specifies a domain name suffix used to distinguish between the audited 
                  infrastructure and third-party sites. Host names that match -d values 
                  will be subjected to analysis, and ones that do not will be considered 
                  the outside world. Interactions between these two classes will be 
                  subjected to additional checks.

                  NOTE: This feature is extremely important for several of the checks 
                  implemented by ratproxy. If -d option is missing, ratproxy will treat 
                  all URLs as being a part of the audited service, and cross-domain 
                  interaction checks will not be carried out at all. If it is set
                  incorrectly, report coverage may decrease.

                  Multiple -d options may and often should be combined to define the 
                  perimeter for testing and flow analysis (e.g., -d example.com -d
                  example-ads-service.com -d example-ng.com).

  -P host:port  - causes ratproxy to talk to an upstream proxy instead of directly 
                  routing requests to target services. Useful for testing systems behind 
                  corporate proxies, or chaining  multiple proxy-type security testing
                  tools together.

  -l            - ratproxy sometimes needs to tell if a page has substantially changed 
                  between two requests to better qualify the risks associated with some 
                  observations. By default, this is achieved through strict page 
                  checksum comparison (MD5). This options enables an alternative, 
                  relaxed checking mode that relies on page length comparison instead.

                  Since some services tend to place dynamically generated tokens on 
                  rendered pages, it is generally advisable to enable this mode most
                  of the time.

  -2            - several services are known to render the same page with dynamic content 
                  of variable length in response to two subsequent, otherwise identical 
                  requests. This might be a result of inline ad rendering, or other 
                  content randomization.

                  When dealing with such services, ratproxy might be instructed to 
                  acquire three, not two, samples for page comparison for some checks,
                  to further minimize the number of false positives.

  -e            - enables pedantic caching header validation. Security problems may arise
                  when documents clearly not meant to be cached are served in a way that 
                  permits public proxies to store them. By default, ratproxy detects 
                  poorly chosen HTTP/1.1 caching directives that are most likely to 
                  affect general population.

                  Some additional issues may appear with users behind legacy proxies
                  that support HTTP/1.0 only, however - as is the case with several 
                  commercial solutions. These proxies may ignore HTTP/1.1 directives and 
                  interpret HTTP/1.0 cues only. In -e mode, ratproxy will complain about
                  all cases where there appears to be a mismatch between HTTP/1.0 and 
                  HTTP/1.1 caching intents.

                  This tends to generate a large number of warnings for many services;
                  if you prefer to focus on more pressing issues first, you might want to
                  keep it off at first.

  -x            - tells the proxy to log all URLs that seem to be particularly
                  well-suited for further, external XSS testing (by the virtue of being
                  echoed on the page in a particular manner). By default, ratproxy will 
                  not actually attempt to confirm these vectors (-X option enables 
                  disruptive checking, however) - but you will be able to use the data
                  for manual testing or as input to third-party software.

                  Generally recommended, unless it proves to be too noisy.

  -t            - by default, ratproxy logs some of the most likely directory traversal 
                  candidates. This option tells the proxy to log less probable guesses, 
                  too. These are good leads for manual testing or as input to an 
                  external application.

                  Generally recommended, unless it proves to be too noisy.

  -i            - with this option supplied, ratproxy will log all PNG files served 
                  inline. PNG files are a cross-site scripting vector in some legacy
                  browsers. The default behavior is to log these images that require 
                  authentication only, based on the assumption that such images are most 
                  likely to be user-controlled.

                  This option should be enabled when auditing applications that permit 
                  picture uploads and sharing; otherwise, it may just generate noise.

  -f            - with this option enabled, the proxy will log all Flash applications 
                  encountered for further analysis. This is particularly useful when 
                  combined with -v, in which case, Flash files will be automatically 
                  disassembled and conveniently included in 'ratproxy-report.sh' output.

                  Since recent Flash vulnerabilities make the platform a major 
                  potential cross-site scripting vector, it is advisable to enable this
                  feature.

  -s            - tells ratproxy to log all POST requests for further analysis and 
                  processing, in a separate section of the final report. This is useful 
                  for bookkeeping and manual review, since POST features are particularly 
                  likely to expose certain security design flaws.

  -c            - enables logging of all URLs that seem to set cookies, regardless of 
                  their presumed security impact. Again, useful for manual design 
                  analysis and bookkeeping. Not expected to contribute much noise to
                  the report.

  -g            - extends XSRF token validation checks to GET requests. By default, the 
                  proxy requires anti-XSRF protection on POST requests and cookie
                  setters only. Some applications tend to perform state changing 
                  operations via GET requests, too, and so with this option enabled, 
                  additional data will be collected and analyzed.

                  This feature is verbose, but useful for certain application designs.

  -j            - enables detection of discouraged Javascript syntax, such as eval() 
                  calls or .innerHTML operations. Javascript code that makes use of 
                  these will be tagged for manual inspection.

  -m            - enables logging of "active" content referenced across domain boundaries
                  to detect patterns such as remote image inclusion or remote linking
                  (note that logging of remote script or stylesheet inclusion is enabled 
                  at all times).

                  This option has an effect only when a proper set of domains is 
                  specified with -d command-line parameter - and is recommended for sites
                  where a careful control of cross-domain trust relationships needs to
                  be ensured.

  -X            - enables active testing. When this option is provided, ratproxy will 
                  attempt to actively, disruptively validate the robustness of XSS
                  and XSRF defenses whenever such a check is deemed necessary. By the 
                  virtue of doing passive preselection, this does not generate excessive 
                  traffic and maintains the same level of coverage as afforded in passive
                  mode.

                  The downside is that these additional requests may disrupt the 
                  application or even trigger persistent problems; as such, please 
                  exercise caution when using it against mission-critical production
                  systems.

  -C            - in disruptive testing mode, ratproxy will replay some requests with 
                  modified parameters. This may disrupt the state of some applications 
                  and make them difficult to navigate.  To remediate this, -C option 
                  enables additional replaying of the unmodified request at the end of 
                  the process, in hopes of restoring the original server-side state.

                  This option is generally recommended in -X mode.

  -k            - instructs ratproxy that the application is expected to use HTTPS 
                  exclusively; any downgrades to HTTP will be reported and prioritized 
                  depending on potential impact.

                  This option obviously makes sense only if the application is indeed 
                  meant to use HTTPS and HTTPS only.

  -a            - tells ratproxy to indiscriminately log all visited URLs. Useful for
                  assessing the coverage achieved.
```

In practice, for low verbosity reporting that looks for high-probability issues only, a good starting point is:

> `./ratproxy -v <outdir> -w <outfile> -d <domain> -lfscm`

To increase verbosity and include output from some less specific checks, the following set of options is a good idea:

> `./ratproxy -v <outdir> -w <outfile> -d <domain> -lextifscgjm`

For active testing, simply add `-XC` options as needed.

Once the proxy is running, you need to configure your web browser to point to the appropriate machine and port (a simple Firefox extension such as [QuickProxy](https://addons.mozilla.org/en-US/firefox/addon/1557) may come handy in the long run); it is advisable to close any non-essential browser windows and purge browser cache, as to maximize coverage and minimize noise.

The next step is to open the tested service in your browser, log in if necessary, then interact with it in a regular, reasonably exhaustive manner: try all available views, features, upload and download files, add and delete data, and so forth - then log out gracefully and terminate _ratproxy_ with `Ctrl-C`.

> **NOTE:** Do not be tempted to tunnel automated spider traffic (e.g. `wget -r` or active scanners) via _ratproxy_. This will not have the desired effect. The tool depends strictly on being able to observe well-behaved, valid user-application interaction.

> **SECURITY WARNING:** When interacting with SSL applications, _ratproxy_ will substitute its own, dummy, self-signed certificate in place of that legitimately returned by the service. This is expected to generate browser warnings - click through them to accept the key temporarily for the site. Do not add the key permanently to your browser configuration - the key is known to anyone who ever downloaded the tool. Furthermore, please note that _ratproxy_ will also forego any server certificate validation steps - so while interacting with the service in this mode, you can have no expectation of server identity, transmission integrity, or data privacy. Do not use important accounts and do not enter sensitive data while running _ratproxy_ tests.

Once the proxy is terminated, you may further process its pipe-delimited (`|`), machine-readable, greppable output with third party tools if so desired, then generate a human-readable HTML report:

> `./ratproxy-report.sh ratproxy.log >report.html`

This will produce an annotated, prioritized report with all the identified issues. When opened in a browser, you will have an opportunity to replay GET and POST requests, tweak their parameters, view traces, and inspect Flash disassemblies, too.

Enjoy :-)

## Credits, contributions, suggestions ##

If you are interested in contributing to the project, a list of features and improvements for the proxy can be found in `doc/TODO` in the source tarball.

If you have any questions, suggestions, or concerns regarding the application, the author can be reached at [lcamtuf@google.com](mailto:lcamtuf@google.com).

`Ratproxy` was made possible by the contributions of, and valuable feedback from, Google's information security engineering team.