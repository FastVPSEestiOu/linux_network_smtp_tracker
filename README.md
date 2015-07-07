linux_network_smtp_tracker
==============================

**linux_network_activity_tracker** - little software for detecting OpenVZ containers with the number outgoing SMTP-connections greater then specifed limit.

It is based on  [linux_network_activity_tracker](https://github.com/FastVPSEestiOu/linux_network_activity_tracker)

Install
-------
[![Build Status](https://travis-ci.org/FastVPSEestiOu/linux_network_smtp_tracker.svg?branch=master)](https://travis-ci.org/FastVPSEestiOu/linux_network_smtp_tracker)

```
export GOPATH=$(pwd)
go get github.com/FastVPSEestiOu/linux_network_smtp_tracker
go build github.com/FastVPSEestiOu/linux_network_smtp_tracker
```

And copy binary file to directory in $PATH if it needed.

Usage
-------
```
linux_network_smtp_tracker [-j] [ -m max_count_smtp_connections ]
```

Options
-------
- --help

Print usage message (build in from flag library)

- -j

Enable json output

- -m max_count_smtp_connections

Set max count of outgoing smtp connections. If it greater limit - we saw container in output

Description
-----------

We get connections from /proc/net/ files(tcp,tcp6).
Buid /proc/?/fd/ map if we have outgoing smtp connectons(25 and 587 ports via tcp).
Get info about process, who start this connections - get CTID.
And output this info to OUTPUT in human readable fromat or in json format, if connections count on countainer greater that our limit(like ctid - count connections from contaner).


Contributors
------------
- [Sergei Mamonov](https://github.com/mrqwer88)
