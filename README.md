Plecost
=======


![Logo](https://raw.githubusercontent.com/iniqua/plecost/develop/plecost/doc/screenshots/logo_plecost.jpg "Plecost Logo")

Wordpress finger printer tool, plecost search and retrieve information about the plugins versions installed in Wordpress systems. Additionally displays CVE code associated with each plugin, if there.

Plecost retrieves the information contained on Web sites supported by Wordpress.

Quick help
----------

```
$ python plecost/plecost.py -h

```
```

$ python plecost.py -h

///////////////////////////////////////////////////////
// ..................................DMI...
// .............................:MMMM......
// .........................$MMMMM:........
// .........M.....,M,=NMMMMMMMMD...........
// ........MMN...MMMMMMMMMMMM,.............
// .......MMMMMMMMMMMMMMMMM~...............
// .......MMMMMMMMMMMMMMM..................
// ....?MMMMMMMMMMMMMMMN$I.................
// .?.MMMMMMMMMMMMMMMMMMMMMM...............
// .MMMMMMMMMMMMMMN........................
// 7MMMMMMMMMMMMMON$.......................
// ZMMMMMMMMMMMMMMMMMM.......plecost.......
// .:MMMMMMMZ~7MMMMMMMMMO..................
// ....~+:.................................
//
// Plecost - Wordpress finger printer Tool - v0.3.0
//
// Developed by:
//        Francisco Jesus Gomez aka ffranz | @ffranz - ffranz-[at]-iniqua.com
//        Daniel Garcia aka cr0hn | @ggdaniel - cr0hn-[at]-cr0hn.com
//
// Info: http://iniqua.com/labs/
// Bug report: plecost@iniqua.com

usage: plecost.py [-h] [-v] [-o OUTPUT_FILE] [-w WORDLIST] [--list-wordlist]
                  [--concurrency CONCURRENCY] [--proxy PROXY]
                  [--update-cve UPDATE_CVE] [--update-plugins]
                  [--update-all UPDATE_ALL]
                  [TARGET [TARGET ...]]

Plecost: Wordpress finger printer tool

positional arguments:
  TARGET

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -o OUTPUT_FILE        report file with extension: xml|json

wordlist options:
  -w WORDLIST, --wordlist WORDLIST
                        set custom word list. Default 200 most common
  --list-wordlist       list embedded available word list

advanced options:
  --concurrency CONCURRENCY
                        number of parallel processes.
  --proxy PROXY         proxy as format proxy:port.

update options:
  --update-cve UPDATE_CVE
                        Update CVE database.
  --update-plugins      Update plugins.
  --update-all UPDATE_ALL
                        Update CVE, plugins, and core.

Examples:

    * Scan target using default 200 most common plugins:
        plecost TARGET
    * List available word lists:
        plecost --list-wordlist
    * Use embedded 2000 most commont word list:
        plecost -w plugin_list_2000.txt TARGET
    * Scan, using 10 concurrent network connections:
        plecost -w plugin_list_2000.txt --concurrency 10 TARGET
    * Scan using verbose mode and generate xml report:
        plecost -w plugin_list_2000.txt --concurrency 10 -o report.xml TARGET
    * Scan using verbose mode and generate json report:
        plecost -vvv --concurrency 10 -o report.json TARGET

```

How its works?
--------------

![Run example](https://raw.githubusercontent.com/iniqua/plecost/develop/plecost/doc/screenshots/runexample.png "Run example")

Where to fish?
--------------

Plecost is available on:

* BackTrack 5 http://www.backtrack-linux.org/
* BackBox http://www.backbox.org/


References
----------

* http://www.securitybydefault.com/2010/03/seguridad-en-wordpress.html
* http://www.securitybydefault.com/2011/11/identificacion-de-vulnerabilidades-en.html
* http://www.clshack.it/plecost-a-wordpress-penetration-test-for-plugins
* http://securityetalii.wordpress.com/2010/03/06/auditando-wordpress-con-plecost/
* http://loginroot.diosdelared.com/?coment=6116
* http://ayudawordpress.com/securidad-en-wordpress/
* http://www.ehacking.net/2012/05/wordpress-security-vulnerability.html 
