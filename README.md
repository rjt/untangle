untangle
========

Untangle did not force SSL very well.  It was too easy to bookmark 
a URL and unknowningly enter your credentials in the "clear"
because the protection mechanism were bypassed.  This adds some
defense in depth.

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
is to file an issue at github.com/rjt/untangle .

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
