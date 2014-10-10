untangle
========

Untangle does not force SSL very well as of 2014-10-09.  
It was too easy to bookmark 
a URL and unknowningly enter your credentials in the "clear"
because the protection mechanism were bypassed.  
Enter 

http://MyUntangleFirewall.com/auth/login?url=/setup/welcome.do&realm=Administrator

and see if you can put your username and password into the box
and that submit will transmit them even if http administration
is turned off.

1.) Make a backup of the corresponding files on your system.
2.) mkdir ./archive/ Move the corresponding '*.pyc' files.
3.) copy these files to their locations on your gateway.
4.) There will be a corresponding 
5.) Verify it is installed by:

     ssh root@untangle
     # grep rjt /var/log/apache2/error.log
    
6.) Verify it is working by testing the public and private URLs found here: 
     # grep '\[crit\] rjt' /var/log/apache2/error.log | grep http 

will tell you the URL to put into a test browser to
see if SSL / https is bypassed when prompted for
credentials.



These "patches" adds some defense in depth.

This is a hack to force https://

The directory structure is deep, but there is only a few files
or less.  

pushd to this directory and enter find .
which will point you to index.py.
i lied, now that it is under source control,
all the .git files show up.  
find . | grep -v '^\./\.'

We further noticed that in at least a few places,
when untangle checks for "localhost", it does not
consider IPv6.  Matching against '127\.' but
not '\:\:1'.  uvmlogin.py _begins_ to draw attention 
to industry-wide localhost problems. 

If you have questions on what to do with these
files, probably the best way to reach me
is to file an issue at https://github.com/rjt/untangle/issues/ .

Robert Townley
rob.townley+untangle@gmail.com

=============
List of folders and files:
.
./usr
./usr/share
./usr/share/untangle
./usr/share/untangle/mod_python
./usr/share/untangle/mod_python/auth
./usr/share/untangle/mod_python/auth/index.py  #This file forces https.
./usr/share/untangle/mod_python/auth/index.py-original
./usr/lib
./usr/lib/python2.6
./usr/lib/python2.6/uvmlogin.py  #This file starts to check for IPv6 localhost.
./ReadMeUntanglePatches.md
./findUntangleFiles.sh
./LICENSE
./README.md
