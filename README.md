Plecost
=======


![Logo](https://raw.githubusercontent.com/iniqua/plecost/develop/plecost_lib/doc/images/logo_plecost.jpg)


*Plecost: Wordpress vulnerabilities finder*

Code | https://github.com/iniqua/plecost/tree/python3
---- | ----------------------------------------------
Issues | https://github.com/iniqua/plecost/tree/python3/issues
Python version | Python 3.3 and above
Authors | @ggdaniel (cr0hn) - @ffranz (ffr4nz)
Last version | 1.1.1

What's Plecost?
---------------

Plecost is a vulnerability fingerprinting and vulnerability finder for Wordpress blog engine. 

Why?
----

There are a huge number of Wordpress around the world. Most of them are exposed to be attacked and be converted into a virus, malware or illegal porn provider, without the knowledge of the blog owner.
   
This project try to help sysadmins and blog's owners to make a bit secure their Wordpress.

What's new?
-----------

### Plecost 3.1.1

- Updated CVE database & Wordpress plugin list.
- Fixed CVE & Wordpress plugins updater.
- Performance tips
- Open Issues

You can read entire list in [CHANGELOG](https://github.com/iniqua/plecost/blob/develop/CHANGELOG.md) file.

### Plecost 3.0.0

This Plecost 3.0.0 version, add a lot of new features and fixes, like:

- Fixed a lot of bugs.
- New engine: without threads or any dependencies, but run more faster. We'll used python 3 asyncio and non-blocking connections. Also consume less memory. Incredible, right? :) 
- Changed CVE update system and storage: Now Plecost get vulnerabilities directly from NIST and create a local SQLite data base with filtered information for Wordpress and theirs plugins.
- Wordpress vulnerabilities: Now Plecost also manage Wordpress Vulnerabilities (not only for the Plugins).
- Add local vulnerability database are queryable. You can consult the vulnerabilities for a concrete wordpress or plugins without, using the local database.


You can read entire list in [CHANGELOG](https://github.com/iniqua/plecost/blob/develop/CHANGELOG.md) file.


Installation
------------

### Using Pypi

Install Plecost is so easy:

```bash
> python3 -m pip install plecost
```

**Remember that Plecost3 only runs in Python 3**.
 
### Using Docker

If you don't want to install Plecost, you can run it using Docker:

```bash
> docker run --rm iniqua/plecost {ARGS}
```

Where *{ARGS}* is any valid argument of Plecost. A real example could be:

```bash
> docker run --rm iniqua/plecost -nb -w plugin_list_10.txt http://SITE.com
```

Quick start
-----------

Scan a web site si so simple:

```bash
> plecost http://SITE.com
```

A bit complex scan: increasing verbosity exporting results in JSON format and XML:

*JSON*

```bash
> plecost -v http://SITE.com -o results.json
```

*XML*

```bash
> plecost -v http://SITE.com -o results.xml
```

Advanced scan options
---------------------

No check WordPress version, only for plugins:

```bash
> plecost -nc http://SITE.com 
```

**Force scan**, even if not Wordpress was detected:

```bash
> plecost -f http://SITE.com
```

Display only the short banner:

```bash
> plecost -nb http://SITE.com
```

List available wordlists:

```bash
> plecost -nb -l 

// Plecost - Wordpress finger printer Tool - v1.0.0

Available word lists:
   1 - plugin_list_10.txt
   2 - plugin_list_100.txt
   3 - plugin_list_1000.txt
   4 - plugin_list_250.txt
   5 - plugin_list_50.txt
   6 - plugin_list_huge.txt
```

Select a wordlist in the list:

```bash
> plecost -nb -w plugin_list_10.txt http://SITE.com
```

Increasing concurrency (**USE THIS OPTION WITH CAUTION. CAN SHUTDOWN TESTED SITE!**)

```bash
> plecost --concurrency 10 http://SITE.com
```

Or...

```bash
> plecost -c 10 http://SITE.com
```

*For more options, consult the --help command*:


```bash
> plecost -h
```

Updating
--------

New versions and vulnerabilities are released diary, you can upload the local database writing:

Updating vulnerability database:

```bash
> plecost --update-cve
```

Updating plugin list:

```bash
> plecost --update-plugins
```

Reading local vulnerability database
------------------------------------

Plecost has a local vulnerability database of Wordpress and wordpress plugins. You can consult it in off-line mode.

Listing all known plugins with vulnerabilities:

```bash
> plecost -nb --show-plugins
  
// Plecost - Wordpress finger printer Tool - v1.0.0

[*] Plugins with vulnerabilities known:

  { 0 } - acobot_live_chat_%26_contact_form
  { 1 } - activehelper_livehelp_live_chat
  { 2 } - ad-manager
  { 3 } - alipay
  { 4 } - all-video-gallery
  { 5 } - all_in_one_wordpress_security_and_firewall
  { 6 } - another_wordpress_classifieds_plugin
  { 7 } - anyfont
  { 8 } - april%27s_super_functions_pack
  { 9 } - banner_effect_header
  { 10 } - bannerman
  { 11 } - bib2html
  { 12 } - bic_media_widget
  { 13 } - bird_feeder
  { 14 } - blogstand-smart-banner
  { 15 } - blue_wrench_video_widget
  ...
  
[*] Done!
```

Show vulnerabilities of a concrete plugin:

```bash
> plecost -nb -vp google_analytics
          
// Plecost - Wordpress finger printer Tool - v1.0.0

[*] Associated CVEs for plugin 'google_analytics':

  { 0 } - CVE-2014-9174:

           Affected versions:

           <0> - 5.1.2
           <1> - 5.1.1
           <2> - 5.1
           <3> - 5.1.0

[*] Done!
```
          
Show details of a concrete CVE:
          
```bash
> plecost -nb --cve CVE-2014-9174
          
// Plecost - Wordpress finger printer Tool - v1.0.0

[*] Detail for CVE 'CVE-2014-9174':

  Cross-site scripting (XSS) vulnerability in the Google Analytics by Yoast (google-analytics-for-wordpress) plugin before 5.1.3 for WordPress allows remote attackers to inject arbitrary web script or HTML via the "Manually enter your UA code" (manual_ua_code_field) field in the General Settings.


[*] Done!

```

Examples
--------

Getting the [100k top WordPress sites (http://hackertarget.com/100k-top-wordpress-powered-sites/) and getting aleatory one of them...
  
![running](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/running.gif)
           
And... here more results of Plecost for real sites... :)
 
![Example1](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/scan_example1.png)
![Example2](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/scan_example2.png)
![Example3](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/scan_example3.png)
![Example4](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/scan_example4.png)
![Example5](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/scan_example5.png)
![Example6](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/scan_example6.png)
![Example7](https://raw.githubusercontent.com/iniqua/plecost/python3/plecost_lib/doc/images/scan_example7.png)

Where to fish?
--------------

Plecost is available on:

* Kali Linux http://www.kali.org/
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
