import glob
import os

s = '''CWE-20 	Python 	py/count-untrusted-data-external-api 	Frequency counts for external APIs that are used with untrusted data
CWE-20 	Python 	py/untrusted-data-to-external-api 	Untrusted data passed to external API
CWE-20 	Python 	py/incomplete-hostname-regexp 	Incomplete regular expression for hostnames
CWE-20 	Python 	py/incomplete-url-substring-sanitization 	Incomplete URL substring sanitization
CWE-20 	Python 	py/overly-large-range 	Overly permissive regular expression range
CWE-20 	Python 	py/bad-tag-filter 	Bad HTML filtering regexp
CWE-22 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-22 	Python 	py/tarslip 	Arbitrary file write during tarfile extraction
CWE-22 	Python 	py/zipslip 	Arbitrary file access during archive extraction ("Zip Slip")
CWE-22 	Python 	py/tarslip-extended 	Arbitrary file write during tarfile extraction
CWE-22 	Python 	py/unsafe-unpacking 	Arbitrary file write during a tarball extraction from a user controlled source
CWE-23 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-36 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-73 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-73 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-74 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-74 	Python 	py/command-line-injection 	Uncontrolled command line
CWE-74 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-74 	Python 	py/jinja2/autoescape-false 	Jinja2 templating with autoescape=False
CWE-74 	Python 	py/reflective-xss 	Reflected server-side cross-site scripting
CWE-74 	Python 	py/sql-injection 	SQL query built from user-controlled sources
CWE-74 	Python 	py/ldap-injection 	LDAP query built from user-controlled sources
CWE-74 	Python 	py/code-injection 	Code injection
CWE-74 	Python 	py/xpath-injection 	XPath query built from user-controlled sources
CWE-74 	Python 	py/nosql-injection 	NoSQL Injection
CWE-74 	Python 	py/template-injection 	Server Side Template Injection
CWE-74 	Python 	py/paramiko-command-injection 	RCE with user provided command with paramiko ssh client
CWE-74 	Python 	py/reflective-xss-email 	Reflected server-side cross-site scripting
CWE-74 	Python 	py/xslt-injection 	XSLT query built from user-controlled sources
CWE-74 	Python 	py/header-injection 	HTTP Header Injection
CWE-77 	Python 	py/command-line-injection 	Uncontrolled command line
CWE-77 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-78 	Python 	py/command-line-injection 	Uncontrolled command line
CWE-78 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-79 	Python 	py/jinja2/autoescape-false 	Jinja2 templating with autoescape=False
CWE-79 	Python 	py/reflective-xss 	Reflected server-side cross-site scripting
CWE-79 	Python 	py/reflective-xss-email 	Reflected server-side cross-site scripting
CWE-79 	Python 	py/header-injection 	HTTP Header Injection
CWE-88 	Python 	py/command-line-injection 	Uncontrolled command line
CWE-88 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-89 	Python 	py/sql-injection 	SQL query built from user-controlled sources
CWE-90 	Python 	py/ldap-injection 	LDAP query built from user-controlled sources
CWE-91 	Python 	py/xpath-injection 	XPath query built from user-controlled sources
CWE-91 	Python 	py/xslt-injection 	XSLT query built from user-controlled sources
CWE-93 	Python 	py/header-injection 	HTTP Header Injection
CWE-94 	Python 	py/code-injection 	Code injection
CWE-95 	Python 	py/code-injection 	Code injection
CWE-99 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-113 	Python 	py/header-injection 	HTTP Header Injection
CWE-116 	Python 	py/reflective-xss 	Reflected server-side cross-site scripting
CWE-116 	Python 	py/code-injection 	Code injection
CWE-116 	Python 	py/bad-tag-filter 	Bad HTML filtering regexp
CWE-116 	Python 	py/log-injection 	Log Injection
CWE-116 	Python 	py/reflective-xss-email 	Reflected server-side cross-site scripting
CWE-117 	Python 	py/log-injection 	Log Injection
CWE-172 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-176 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-179 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-180 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-185 	Python 	py/bad-tag-filter 	Bad HTML filtering regexp
CWE-186 	Python 	py/bad-tag-filter 	Bad HTML filtering regexp
CWE-200 	Python 	py/bind-socket-all-network-interfaces 	Binding a socket to all network interfaces
CWE-200 	Python 	py/stack-trace-exposure 	Information exposure through an exception
CWE-200 	Python 	py/flask-debug 	Flask app is run in debug mode
CWE-200 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-200 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-200 	Python 	py/possible-timing-attack-against-hash 	Timing attack against Hash
CWE-200 	Python 	py/timing-attack-against-hash 	Timing attack against Hash
CWE-200 	Python 	py/timing-attack-against-header-value 	Timing attack against header value
CWE-200 	Python 	py/possible-timing-attack-sensitive-info 	Timing attack against secret
CWE-200 	Python 	py/timing-attack-sensitive-info 	Timing attack against secret
CWE-203 	Python 	py/possible-timing-attack-against-hash 	Timing attack against Hash
CWE-203 	Python 	py/timing-attack-against-hash 	Timing attack against Hash
CWE-203 	Python 	py/timing-attack-against-header-value 	Timing attack against header value
CWE-203 	Python 	py/possible-timing-attack-sensitive-info 	Timing attack against secret
CWE-203 	Python 	py/timing-attack-sensitive-info 	Timing attack against secret
CWE-208 	Python 	py/possible-timing-attack-against-hash 	Timing attack against Hash
CWE-208 	Python 	py/timing-attack-against-hash 	Timing attack against Hash
CWE-208 	Python 	py/timing-attack-against-header-value 	Timing attack against header value
CWE-208 	Python 	py/possible-timing-attack-sensitive-info 	Timing attack against secret
CWE-208 	Python 	py/timing-attack-sensitive-info 	Timing attack against secret
CWE-209 	Python 	py/stack-trace-exposure 	Information exposure through an exception
CWE-215 	Python 	py/flask-debug 	Flask app is run in debug mode
CWE-221 	Python 	py/catch-base-exception 	Except block handles 'BaseException'
CWE-227 	Python 	py/equals-hash-mismatch 	Inconsistent equality and hashing
CWE-227 	Python 	py/call/wrong-named-class-argument 	Wrong name for an argument in a class instantiation
CWE-227 	Python 	py/call/wrong-number-class-arguments 	Wrong number of arguments in a class instantiation
CWE-227 	Python 	py/super-not-enclosing-class 	First argument to super() is not enclosing class
CWE-227 	Python 	py/call/wrong-named-argument 	Wrong name for an argument in a call
CWE-227 	Python 	py/percent-format/wrong-arguments 	Wrong number of arguments for format
CWE-227 	Python 	py/call/wrong-arguments 	Wrong number of arguments in a call
CWE-252 	Python 	py/ignored-return-value 	Ignored return value
CWE-259 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-284 	Python 	py/pam-auth-bypass 	PAM authorization bypass due to incorrect usage
CWE-284 	Python 	py/overly-permissive-file 	Overly permissive file permissions
CWE-284 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-284 	Python 	py/flask-constant-secret-key 	Initializing SECRET_KEY of Flask application with Constant value
CWE-284 	Python 	py/improper-ldap-auth 	Improper LDAP Authentication
CWE-284 	Python 	py/insecure-ldap-auth 	Python Insecure LDAP Authentication
CWE-285 	Python 	py/pam-auth-bypass 	PAM authorization bypass due to incorrect usage
CWE-285 	Python 	py/overly-permissive-file 	Overly permissive file permissions
CWE-287 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-287 	Python 	py/flask-constant-secret-key 	Initializing SECRET_KEY of Flask application with Constant value
CWE-287 	Python 	py/improper-ldap-auth 	Improper LDAP Authentication
CWE-287 	Python 	py/insecure-ldap-auth 	Python Insecure LDAP Authentication
CWE-295 	Python 	py/paramiko-missing-host-key-validation 	Accepting unknown SSH host keys when using Paramiko
CWE-295 	Python 	py/request-without-cert-validation 	Request without certificate validation
CWE-311 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-311 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-311 	Python 	py/cookie-injection 	Construction of a cookie using user-supplied input.
CWE-311 	Python 	py/insecure-cookie 	Failure to use secure cookies
CWE-312 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-312 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-315 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-321 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-326 	Python 	py/weak-crypto-key 	Use of weak cryptographic key
CWE-326 	Python 	py/weak-sensitive-data-hashing 	Use of a broken or weak cryptographic hashing algorithm on sensitive data
CWE-326 	Python 	py/unknown-asymmetric-key-gen-size 	Unknown key generation key size
CWE-326 	Python 	py/weak-asymmetric-key-gen-size 	Weak key generation key size (< 2048 bits)
CWE-327 	Python 	py/weak-cryptographic-algorithm 	Use of a broken or weak cryptographic algorithm
CWE-327 	Python 	py/insecure-default-protocol 	Default version of SSL/TLS may be insecure
CWE-327 	Python 	py/insecure-protocol 	Use of insecure SSL/TLS version
CWE-327 	Python 	py/weak-sensitive-data-hashing 	Use of a broken or weak cryptographic hashing algorithm on sensitive data
CWE-327 	Python 	py/azure-storage/unsafe-client-side-encryption-in-use 	Unsafe usage of v1 version of Azure Storage client-side encryption.
CWE-327 	Python 	py/weak-block-mode 	Weak block mode
CWE-327 	Python 	py/weak-elliptic-curve 	Weak elliptic curve
CWE-327 	Python 	py/weak-hashes 	Weak hashes
CWE-327 	Python 	py/weak-symmetric-encryption 	Weak symmetric encryption algorithm
CWE-328 	Python 	py/weak-sensitive-data-hashing 	Use of a broken or weak cryptographic hashing algorithm on sensitive data
CWE-330 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-330 	Python 	py/insecure-randomness 	Insecure randomness
CWE-330 	Python 	py/predictable-token 	Predictable token
CWE-338 	Python 	py/insecure-randomness 	Insecure randomness
CWE-340 	Python 	py/predictable-token 	Predictable token
CWE-344 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-345 	Python 	py/csrf-protection-disabled 	CSRF protection weakened or disabled
CWE-345 	Python 	py/jwt-missing-verification 	JWT missing secret or public key verification
CWE-345 	Python 	py/ip-address-spoofing 	IP address spoofing
CWE-347 	Python 	py/jwt-missing-verification 	JWT missing secret or public key verification
CWE-348 	Python 	py/ip-address-spoofing 	IP address spoofing
CWE-352 	Python 	py/csrf-protection-disabled 	CSRF protection weakened or disabled
CWE-359 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-359 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-377 	Python 	py/insecure-temporary-file 	Insecure temporary file
CWE-390 	Python 	py/empty-except 	Empty except
CWE-396 	Python 	py/catch-base-exception 	Except block handles 'BaseException'
CWE-398 	Python 	py/unreachable-except 	Unreachable 'except' block
CWE-398 	Python 	py/comparison-of-constants 	Comparison of constants
CWE-398 	Python 	py/comparison-of-identical-expressions 	Comparison of identical values
CWE-398 	Python 	py/comparison-missing-self 	Maybe missing 'self' in comparison
CWE-398 	Python 	py/redundant-comparison 	Redundant comparison
CWE-398 	Python 	py/duplicate-key-dict-literal 	Duplicate key in dict literal
CWE-398 	Python 	py/import-deprecated-module 	Import of deprecated module
CWE-398 	Python 	py/constant-conditional-expression 	Constant in conditional expression or statement
CWE-398 	Python 	py/redundant-assignment 	Redundant assignment
CWE-398 	Python 	py/ineffectual-statement 	Statement has no effect
CWE-398 	Python 	py/unreachable-statement 	Unreachable code
CWE-398 	Python 	py/multiple-definition 	Variable defined multiple times
CWE-398 	Python 	py/unused-local-variable 	Unused local variable
CWE-398 	Python 	py/unused-global-variable 	Unused global variable
CWE-400 	Python 	py/file-not-closed 	File is not always closed
CWE-400 	Python 	py/polynomial-redos 	Polynomial regular expression used on uncontrolled data
CWE-400 	Python 	py/redos 	Inefficient regular expression
CWE-400 	Python 	py/regex-injection 	Regular expression injection
CWE-400 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-404 	Python 	py/file-not-closed 	File is not always closed
CWE-405 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-405 	Python 	py/decompression-bomb 	Decompression Bomb
CWE-405 	Python 	py/simple-xml-rpc-server-dos 	SimpleXMLRPCServer denial of service
CWE-409 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-409 	Python 	py/decompression-bomb 	Decompression Bomb
CWE-409 	Python 	py/simple-xml-rpc-server-dos 	SimpleXMLRPCServer denial of service
CWE-441 	Python 	py/full-ssrf 	Full server-side request forgery
CWE-441 	Python 	py/partial-ssrf 	Partial server-side request forgery
CWE-477 	Python 	py/import-deprecated-module 	Import of deprecated module
CWE-485 	Python 	py/flask-debug 	Flask app is run in debug mode
CWE-489 	Python 	py/flask-debug 	Flask app is run in debug mode
CWE-497 	Python 	py/stack-trace-exposure 	Information exposure through an exception
CWE-502 	Python 	py/unsafe-deserialization 	Deserialization of user-controlled data
CWE-522 	Python 	py/insecure-ldap-auth 	Python Insecure LDAP Authentication
CWE-523 	Python 	py/insecure-ldap-auth 	Python Insecure LDAP Authentication
CWE-532 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-538 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-552 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-561 	Python 	py/unreachable-except 	Unreachable 'except' block
CWE-561 	Python 	py/comparison-of-constants 	Comparison of constants
CWE-561 	Python 	py/comparison-of-identical-expressions 	Comparison of identical values
CWE-561 	Python 	py/comparison-missing-self 	Maybe missing 'self' in comparison
CWE-561 	Python 	py/redundant-comparison 	Redundant comparison
CWE-561 	Python 	py/duplicate-key-dict-literal 	Duplicate key in dict literal
CWE-561 	Python 	py/constant-conditional-expression 	Constant in conditional expression or statement
CWE-561 	Python 	py/ineffectual-statement 	Statement has no effect
CWE-561 	Python 	py/unreachable-statement 	Unreachable code
CWE-563 	Python 	py/redundant-assignment 	Redundant assignment
CWE-563 	Python 	py/multiple-definition 	Variable defined multiple times
CWE-563 	Python 	py/unused-local-variable 	Unused local variable
CWE-563 	Python 	py/unused-global-variable 	Unused global variable
CWE-570 	Python 	py/comparison-of-constants 	Comparison of constants
CWE-570 	Python 	py/comparison-of-identical-expressions 	Comparison of identical values
CWE-570 	Python 	py/comparison-missing-self 	Maybe missing 'self' in comparison
CWE-570 	Python 	py/redundant-comparison 	Redundant comparison
CWE-570 	Python 	py/constant-conditional-expression 	Constant in conditional expression or statement
CWE-571 	Python 	py/comparison-of-constants 	Comparison of constants
CWE-571 	Python 	py/comparison-of-identical-expressions 	Comparison of identical values
CWE-571 	Python 	py/comparison-missing-self 	Maybe missing 'self' in comparison
CWE-571 	Python 	py/redundant-comparison 	Redundant comparison
CWE-571 	Python 	py/constant-conditional-expression 	Constant in conditional expression or statement
CWE-573 	Python 	py/equals-hash-mismatch 	Inconsistent equality and hashing
CWE-573 	Python 	py/call/wrong-named-class-argument 	Wrong name for an argument in a class instantiation
CWE-573 	Python 	py/call/wrong-number-class-arguments 	Wrong number of arguments in a class instantiation
CWE-573 	Python 	py/super-not-enclosing-class 	First argument to super() is not enclosing class
CWE-573 	Python 	py/call/wrong-named-argument 	Wrong name for an argument in a call
CWE-573 	Python 	py/percent-format/wrong-arguments 	Wrong number of arguments for format
CWE-573 	Python 	py/call/wrong-arguments 	Wrong number of arguments in a call
CWE-581 	Python 	py/equals-hash-mismatch 	Inconsistent equality and hashing
CWE-584 	Python 	py/exit-from-finally 	'break' or 'return' statement in finally
CWE-601 	Python 	py/url-redirection 	URL redirection from remote source
CWE-610 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-610 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-610 	Python 	py/url-redirection 	URL redirection from remote source
CWE-610 	Python 	py/xxe 	XML external entity expansion
CWE-610 	Python 	py/full-ssrf 	Full server-side request forgery
CWE-610 	Python 	py/partial-ssrf 	Partial server-side request forgery
CWE-611 	Python 	py/xxe 	XML external entity expansion
CWE-614 	Python 	py/cookie-injection 	Construction of a cookie using user-supplied input.
CWE-614 	Python 	py/insecure-cookie 	Failure to use secure cookies
CWE-628 	Python 	py/call/wrong-named-class-argument 	Wrong name for an argument in a class instantiation
CWE-628 	Python 	py/call/wrong-number-class-arguments 	Wrong number of arguments in a class instantiation
CWE-628 	Python 	py/super-not-enclosing-class 	First argument to super() is not enclosing class
CWE-628 	Python 	py/call/wrong-named-argument 	Wrong name for an argument in a call
CWE-628 	Python 	py/percent-format/wrong-arguments 	Wrong number of arguments for format
CWE-628 	Python 	py/call/wrong-arguments 	Wrong number of arguments in a call
CWE-642 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-642 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-643 	Python 	py/xpath-injection 	XPath query built from user-controlled sources
CWE-643 	Python 	py/xslt-injection 	XSLT query built from user-controlled sources
CWE-657 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-664 	Python 	py/catch-base-exception 	Except block handles 'BaseException'
CWE-664 	Python 	py/implicit-string-concatenation-in-list 	Implicit string concatenation in a list
CWE-664 	Python 	py/file-not-closed 	File is not always closed
CWE-664 	Python 	py/bind-socket-all-network-interfaces 	Binding a socket to all network interfaces
CWE-664 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-664 	Python 	py/tarslip 	Arbitrary file write during tarfile extraction
CWE-664 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-664 	Python 	py/code-injection 	Code injection
CWE-664 	Python 	py/stack-trace-exposure 	Information exposure through an exception
CWE-664 	Python 	py/flask-debug 	Flask app is run in debug mode
CWE-664 	Python 	py/pam-auth-bypass 	PAM authorization bypass due to incorrect usage
CWE-664 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-664 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-664 	Python 	py/insecure-temporary-file 	Insecure temporary file
CWE-664 	Python 	py/unsafe-deserialization 	Deserialization of user-controlled data
CWE-664 	Python 	py/url-redirection 	URL redirection from remote source
CWE-664 	Python 	py/xxe 	XML external entity expansion
CWE-664 	Python 	py/polynomial-redos 	Polynomial regular expression used on uncontrolled data
CWE-664 	Python 	py/redos 	Inefficient regular expression
CWE-664 	Python 	py/regex-injection 	Regular expression injection
CWE-664 	Python 	py/overly-permissive-file 	Overly permissive file permissions
CWE-664 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-664 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-664 	Python 	py/full-ssrf 	Full server-side request forgery
CWE-664 	Python 	py/partial-ssrf 	Partial server-side request forgery
CWE-664 	Python 	py/zipslip 	Arbitrary file access during archive extraction ("Zip Slip")
CWE-664 	Python 	py/tarslip-extended 	Arbitrary file write during tarfile extraction
CWE-664 	Python 	py/unsafe-unpacking 	Arbitrary file write during a tarball extraction from a user controlled source
CWE-664 	Python 	py/possible-timing-attack-against-hash 	Timing attack against Hash
CWE-664 	Python 	py/timing-attack-against-hash 	Timing attack against Hash
CWE-664 	Python 	py/timing-attack-against-header-value 	Timing attack against header value
CWE-664 	Python 	py/possible-timing-attack-sensitive-info 	Timing attack against secret
CWE-664 	Python 	py/timing-attack-sensitive-info 	Timing attack against secret
CWE-664 	Python 	py/flask-constant-secret-key 	Initializing SECRET_KEY of Flask application with Constant value
CWE-664 	Python 	py/improper-ldap-auth 	Improper LDAP Authentication
CWE-664 	Python 	py/decompression-bomb 	Decompression Bomb
CWE-664 	Python 	py/insecure-ldap-auth 	Python Insecure LDAP Authentication
CWE-664 	Python 	py/simple-xml-rpc-server-dos 	SimpleXMLRPCServer denial of service
CWE-665 	Python 	py/implicit-string-concatenation-in-list 	Implicit string concatenation in a list
CWE-668 	Python 	py/bind-socket-all-network-interfaces 	Binding a socket to all network interfaces
CWE-668 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-668 	Python 	py/tarslip 	Arbitrary file write during tarfile extraction
CWE-668 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-668 	Python 	py/stack-trace-exposure 	Information exposure through an exception
CWE-668 	Python 	py/flask-debug 	Flask app is run in debug mode
CWE-668 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-668 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-668 	Python 	py/insecure-temporary-file 	Insecure temporary file
CWE-668 	Python 	py/overly-permissive-file 	Overly permissive file permissions
CWE-668 	Python 	py/zipslip 	Arbitrary file access during archive extraction ("Zip Slip")
CWE-668 	Python 	py/tarslip-extended 	Arbitrary file write during tarfile extraction
CWE-668 	Python 	py/unsafe-unpacking 	Arbitrary file write during a tarball extraction from a user controlled source
CWE-668 	Python 	py/possible-timing-attack-against-hash 	Timing attack against Hash
CWE-668 	Python 	py/timing-attack-against-hash 	Timing attack against Hash
CWE-668 	Python 	py/timing-attack-against-header-value 	Timing attack against header value
CWE-668 	Python 	py/possible-timing-attack-sensitive-info 	Timing attack against secret
CWE-668 	Python 	py/timing-attack-sensitive-info 	Timing attack against secret
CWE-668 	Python 	py/insecure-ldap-auth 	Python Insecure LDAP Authentication
CWE-669 	Python 	py/xxe 	XML external entity expansion
CWE-670 	Python 	py/asserts-tuple 	Asserting a tuple
CWE-671 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-674 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-674 	Python 	py/simple-xml-rpc-server-dos 	SimpleXMLRPCServer denial of service
CWE-685 	Python 	py/call/wrong-number-class-arguments 	Wrong number of arguments in a class instantiation
CWE-685 	Python 	py/percent-format/wrong-arguments 	Wrong number of arguments for format
CWE-685 	Python 	py/call/wrong-arguments 	Wrong number of arguments in a call
CWE-687 	Python 	py/super-not-enclosing-class 	First argument to super() is not enclosing class
CWE-691 	Python 	py/catch-base-exception 	Except block handles 'BaseException'
CWE-691 	Python 	py/code-injection 	Code injection
CWE-691 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-691 	Python 	py/asserts-tuple 	Asserting a tuple
CWE-691 	Python 	py/exit-from-finally 	'break' or 'return' statement in finally
CWE-691 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-691 	Python 	py/simple-xml-rpc-server-dos 	SimpleXMLRPCServer denial of service
CWE-693 	Python 	py/count-untrusted-data-external-api 	Frequency counts for external APIs that are used with untrusted data
CWE-693 	Python 	py/untrusted-data-to-external-api 	Untrusted data passed to external API
CWE-693 	Python 	py/incomplete-hostname-regexp 	Incomplete regular expression for hostnames
CWE-693 	Python 	py/incomplete-url-substring-sanitization 	Incomplete URL substring sanitization
CWE-693 	Python 	py/overly-large-range 	Overly permissive regular expression range
CWE-693 	Python 	py/bad-tag-filter 	Bad HTML filtering regexp
CWE-693 	Python 	py/pam-auth-bypass 	PAM authorization bypass due to incorrect usage
CWE-693 	Python 	py/paramiko-missing-host-key-validation 	Accepting unknown SSH host keys when using Paramiko
CWE-693 	Python 	py/request-without-cert-validation 	Request without certificate validation
CWE-693 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-693 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-693 	Python 	py/weak-crypto-key 	Use of weak cryptographic key
CWE-693 	Python 	py/weak-cryptographic-algorithm 	Use of a broken or weak cryptographic algorithm
CWE-693 	Python 	py/insecure-default-protocol 	Default version of SSL/TLS may be insecure
CWE-693 	Python 	py/insecure-protocol 	Use of insecure SSL/TLS version
CWE-693 	Python 	py/weak-sensitive-data-hashing 	Use of a broken or weak cryptographic hashing algorithm on sensitive data
CWE-693 	Python 	py/csrf-protection-disabled 	CSRF protection weakened or disabled
CWE-693 	Python 	py/overly-permissive-file 	Overly permissive file permissions
CWE-693 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-693 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-693 	Python 	py/flask-constant-secret-key 	Initializing SECRET_KEY of Flask application with Constant value
CWE-693 	Python 	py/improper-ldap-auth 	Improper LDAP Authentication
CWE-693 	Python 	py/azure-storage/unsafe-client-side-encryption-in-use 	Unsafe usage of v1 version of Azure Storage client-side encryption.
CWE-693 	Python 	py/jwt-missing-verification 	JWT missing secret or public key verification
CWE-693 	Python 	py/ip-address-spoofing 	IP address spoofing
CWE-693 	Python 	py/insecure-ldap-auth 	Python Insecure LDAP Authentication
CWE-693 	Python 	py/cookie-injection 	Construction of a cookie using user-supplied input.
CWE-693 	Python 	py/insecure-cookie 	Failure to use secure cookies
CWE-693 	Python 	py/unknown-asymmetric-key-gen-size 	Unknown key generation key size
CWE-693 	Python 	py/weak-asymmetric-key-gen-size 	Weak key generation key size (< 2048 bits)
CWE-693 	Python 	py/weak-block-mode 	Weak block mode
CWE-693 	Python 	py/weak-elliptic-curve 	Weak elliptic curve
CWE-693 	Python 	py/weak-hashes 	Weak hashes
CWE-693 	Python 	py/weak-symmetric-encryption 	Weak symmetric encryption algorithm
CWE-696 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-697 	Python 	py/bad-tag-filter 	Bad HTML filtering regexp
CWE-703 	Python 	py/catch-base-exception 	Except block handles 'BaseException'
CWE-703 	Python 	py/empty-except 	Empty except
CWE-703 	Python 	py/ignored-return-value 	Ignored return value
CWE-703 	Python 	py/stack-trace-exposure 	Information exposure through an exception
CWE-705 	Python 	py/catch-base-exception 	Except block handles 'BaseException'
CWE-705 	Python 	py/exit-from-finally 	'break' or 'return' statement in finally
CWE-706 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-706 	Python 	py/tarslip 	Arbitrary file write during tarfile extraction
CWE-706 	Python 	py/xxe 	XML external entity expansion
CWE-706 	Python 	py/zipslip 	Arbitrary file access during archive extraction ("Zip Slip")
CWE-706 	Python 	py/tarslip-extended 	Arbitrary file write during tarfile extraction
CWE-706 	Python 	py/unsafe-unpacking 	Arbitrary file write during a tarball extraction from a user controlled source
CWE-707 	Python 	py/path-injection 	Uncontrolled data used in path expression
CWE-707 	Python 	py/command-line-injection 	Uncontrolled command line
CWE-707 	Python 	py/shell-command-constructed-from-input 	Unsafe shell command constructed from library input
CWE-707 	Python 	py/jinja2/autoescape-false 	Jinja2 templating with autoescape=False
CWE-707 	Python 	py/reflective-xss 	Reflected server-side cross-site scripting
CWE-707 	Python 	py/sql-injection 	SQL query built from user-controlled sources
CWE-707 	Python 	py/ldap-injection 	LDAP query built from user-controlled sources
CWE-707 	Python 	py/code-injection 	Code injection
CWE-707 	Python 	py/bad-tag-filter 	Bad HTML filtering regexp
CWE-707 	Python 	py/log-injection 	Log Injection
CWE-707 	Python 	py/xpath-injection 	XPath query built from user-controlled sources
CWE-707 	Python 	py/nosql-injection 	NoSQL Injection
CWE-707 	Python 	py/template-injection 	Server Side Template Injection
CWE-707 	Python 	py/paramiko-command-injection 	RCE with user provided command with paramiko ssh client
CWE-707 	Python 	py/reflective-xss-email 	Reflected server-side cross-site scripting
CWE-707 	Python 	py/xslt-injection 	XSLT query built from user-controlled sources
CWE-707 	Python 	py/header-injection 	HTTP Header Injection
CWE-707 	Python 	py/unicode-bypass-validation 	Bypass Logical Validation Using Unicode Characters
CWE-710 	Python 	py/equals-hash-mismatch 	Inconsistent equality and hashing
CWE-710 	Python 	py/call/wrong-named-class-argument 	Wrong name for an argument in a class instantiation
CWE-710 	Python 	py/call/wrong-number-class-arguments 	Wrong number of arguments in a class instantiation
CWE-710 	Python 	py/unreachable-except 	Unreachable 'except' block
CWE-710 	Python 	py/super-not-enclosing-class 	First argument to super() is not enclosing class
CWE-710 	Python 	py/comparison-of-constants 	Comparison of constants
CWE-710 	Python 	py/comparison-of-identical-expressions 	Comparison of identical values
CWE-710 	Python 	py/comparison-missing-self 	Maybe missing 'self' in comparison
CWE-710 	Python 	py/redundant-comparison 	Redundant comparison
CWE-710 	Python 	py/duplicate-key-dict-literal 	Duplicate key in dict literal
CWE-710 	Python 	py/call/wrong-named-argument 	Wrong name for an argument in a call
CWE-710 	Python 	py/percent-format/wrong-arguments 	Wrong number of arguments for format
CWE-710 	Python 	py/call/wrong-arguments 	Wrong number of arguments in a call
CWE-710 	Python 	py/import-deprecated-module 	Import of deprecated module
CWE-710 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-710 	Python 	py/constant-conditional-expression 	Constant in conditional expression or statement
CWE-710 	Python 	py/redundant-assignment 	Redundant assignment
CWE-710 	Python 	py/ineffectual-statement 	Statement has no effect
CWE-710 	Python 	py/unreachable-statement 	Unreachable code
CWE-710 	Python 	py/multiple-definition 	Variable defined multiple times
CWE-710 	Python 	py/unused-local-variable 	Unused local variable
CWE-710 	Python 	py/unused-global-variable 	Unused global variable
CWE-732 	Python 	py/overly-permissive-file 	Overly permissive file permissions
CWE-754 	Python 	py/ignored-return-value 	Ignored return value
CWE-755 	Python 	py/catch-base-exception 	Except block handles 'BaseException'
CWE-755 	Python 	py/empty-except 	Empty except
CWE-755 	Python 	py/stack-trace-exposure 	Information exposure through an exception
CWE-772 	Python 	py/file-not-closed 	File is not always closed
CWE-776 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-776 	Python 	py/simple-xml-rpc-server-dos 	SimpleXMLRPCServer denial of service
CWE-798 	Python 	py/hardcoded-credentials 	Hard-coded credentials
CWE-827 	Python 	py/xxe 	XML external entity expansion
CWE-829 	Python 	py/xxe 	XML external entity expansion
CWE-834 	Python 	py/xml-bomb 	XML internal entity expansion
CWE-834 	Python 	py/simple-xml-rpc-server-dos 	SimpleXMLRPCServer denial of service
CWE-913 	Python 	py/code-injection 	Code injection
CWE-913 	Python 	py/unsafe-deserialization 	Deserialization of user-controlled data
CWE-916 	Python 	py/weak-sensitive-data-hashing 	Use of a broken or weak cryptographic hashing algorithm on sensitive data
CWE-918 	Python 	py/full-ssrf 	Full server-side request forgery
CWE-918 	Python 	py/partial-ssrf 	Partial server-side request forgery
CWE-922 	Python 	py/clear-text-logging-sensitive-data 	Clear-text logging of sensitive information
CWE-922 	Python 	py/clear-text-storage-sensitive-data 	Clear-text storage of sensitive information
CWE-943 	Python 	py/sql-injection 	SQL query built from user-controlled sources
CWE-943 	Python 	py/ldap-injection 	LDAP query built from user-controlled sources
CWE-943 	Python 	py/xpath-injection 	XPath query built from user-controlled sources
CWE-943 	Python 	py/nosql-injection 	NoSQL Injection
CWE-943 	Python 	py/xslt-injection 	XSLT query built from user-controlled sources
CWE-1236 	Python 	py/csv-injection 	Csv Injection
CWE-1333 	Python 	py/polynomial-redos 	Polynomial regular expression used on uncontrolled data
CWE-1333 	Python 	py/redos 	Inefficient regular expression'''
import json

codeql_dic = {}
for line in s.splitlines():
    #print(line)
    line_split = line.split(" ",maxsplit=3)
    #print(line_split)
    cwe = line_split[0]
    name = line_split[3].strip("\t")
    #print(name)
    if name not in codeql_dic:
        codeql_dic[name] = []
    codeql_dic[name].append(cwe)




import json
positive_out = "gptfiltered/positive_out.out"
err = "gptfiltered/err.out"
with open(positive_out, "r") as f:
    lst = [json.loads(line) for line in f.read().splitlines()]

with open(err, "r") as f:
    err_lst = [json.loads(line) for line in f.read().splitlines()]

import random
import csv

with open("commits_cwe_dic_all.json","r") as f:
    commit_cwe_dic = json.load(f)
with open("all_vul_all.json","r") as f:
    existing_commit_rows = json.load(f)

existing_dic = {}
for row in existing_commit_rows:
    hash = row["hash"]
    repo_url = row["repo_url"][:-4]
    c = repo_url + "/commit/" + hash
    if c not in existing_dic:
        existing_dic[c] = row

for line in err_lst:
    commit = line["commit"]
    if commit in existing_dic:
        existing_dic.pop(commit)




count = 0
py_lst = []
commit_dic = {}
cwe_dic = {}
cwe_dic_lines = {}
for line in lst:
    commit = line["commit"]
    if commit not in existing_dic:
        continue
    if line["programming_language"]!="Python":
        continue

    if commit not in commit_cwe_dic:
        print(commit)
        print(commit in existing_dic)
        raise Exception()
    cwe = commit_cwe_dic[commit]
    if commit not in commit_dic:
        commit_dic[commit]=[]
    commit_dic[commit].append(line)

import csv
# interpret results
csv_file_dic = {}
mark_dic = {}
count_report_dic = {}
count_csrf = 0
cwe_match_list = []
for csv_file in glob.glob("/home/sdb/haowei/vul/codeql_results_latest/*.csv"):
    file_name = os.path.basename(csv_file)
    file_name = file_name[:-4]
    ns = file_name.rsplit("_",1)
    if ns[0].count("_")>1:
        print("warning")
        print(ns[0])

    repo = "https://github.com/"+ns[0].replace("_","/")+"/"
    commit = ns[1]
    commit_link = repo+"commit/"+commit
    if commit_link not in commit_dic:
        print("remove broken")
        continue
    # print(commit_link)

    report_cwe = commit_cwe_dic[commit_link]
    # g_location = file_name.index("GHSA")
    # id = file_name[g_location:-4]
    with open(csv_file,"r") as f:
        reader = csv.reader(f)
        count_dic = {}
        mark = False
        for row in reader:
            description = row[0]

            # if "CSRF protection" in description and not mark:
            #     mark=True
            #     count_csrf+=1
            cwe = None
            for entry,v in codeql_dic.items():
                if entry in description:
                    cwe = v
                    for i in cwe:
                        if i not in count_dic:
                            count_dic[i]=[]
                        count_dic[i].append(row)
                    break
            if not cwe:
                print("error")
                print("row")
    # print(csv_file)
    # print(count_dic)
    # print(report_dic[id])

    # count_report_dic[report_cwe] += 1
    # print(report_dic[id] in count_dic)
    file_dict = {}
    file_dict["report_cwe"] = report_cwe
    file_dict["commit_link"] = commit_link
    file_dict["report"] = commit_dic[commit_link][0]["report_link"]
    file_dict["results"] = count_dic
    if report_cwe in count_dic:
        file_dict["cwe_match"] = True
        file_dict["relevant_results"] = count_dic[report_cwe]
        cwe_match_list.append(file_dict)
    else:
        file_dict["cwe_match"] = False
        file_dict["relevant_results"] = []
    csv_file_dic[csv_file] = file_dict
    if report_cwe not in count_report_dic:
        count_report_dic[report_cwe] = []
    count_report_dic[report_cwe].append(file_dict)
# true = [value for value in mark_dic.values() if value]
# print(len(mark_dic))
# print(len(true))
# mark_dic_cwe = {}
# for id,v in mark_dic.items():
#     if v:
#         if report_dic[id] not in mark_dic_cwe:
#             mark_dic_cwe[report_dic[id]] = 1
#         else:
#             mark_dic_cwe[report_dic[id]] += 1
#
# print(mark_dic_cwe)
# print(count_report_dic)
# true_dic = {}
# for k,v in mark_dic.items():
#     if v:
#         true_dic[k]= True

with open("single_multi_func.out","r") as f:
    single_multi_func = json.load(f)
c = 0
single = 0
multi = 0
for cwe,file_ls in count_report_dic.items():
    for file in file_ls:
        commit = file["commit_link"]
        cwe = file["report_cwe"]
        if commit in single_multi_func["single"]:
            single+=1
        else:
            multi+=1

print("single")
print(single)
print(multi)
import random
print("len cwe match")
print(len(cwe_match_list))


targets = ["https://github.com/mkdocs/mkdocs/commit/57540911a0d632674dd23edec765189f96f84f6b","https://github.com/streamlit/streamlit/commit/afcf880c60e5d7538936cc2d9721b9e1bc02b075"
           ,"https://github.com/caronc/apprise/commit/e20fce630d55e4ca9b0a1e325a5fea6997489831"]
print("target")
for target in targets:
    print(target in single_multi_func["single"])

single = 0
multi = 0
cwe_dic = {}
for file in cwe_match_list:
    commit = file["commit_link"]
    cwe = file["report_cwe"]
    if cwe not in cwe_dic:
        cwe_dic[cwe]=[]
    cwe_dic[cwe].append(file)
    if commit in single_multi_func["single"]:
        single += 1
    else:
        multi += 1
print("single")
print(single)
print(multi)

for cwe,ls in cwe_dic.items():
    print(cwe)
    print(len(ls))



with open("/home/sdb/haowei/vul/codeql_samples.out","r")as f:
    js = [json.loads(line) for line in f.read().splitlines()]

count = 0
sample_dic = []
for line in js:
    commit = line["commit_link"]
    if commit in commit_dic:
        count+=1
        sample_dic.append(line)
        print(commit)
print(count)

with open("codeql_samples.out","w")as f:
    for file in sample_dic:
        f.write(json.dumps(file))
        f.write("\n")
    with open(f"new_review/codeql_samples{50-count}.out", "w")as f:
        for file in random.sample(cwe_match_list, 50-count):
            file.pop("results")
            f.write(json.dumps(file))
            f.write("\n")

print(f"count_csrf {count_csrf}")

