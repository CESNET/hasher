# hasher
Verifies and computes checksums of file contents and stores it in its extended attributes

To use hasher app, it is necessary to compile the source file hasher.c. For compilation is neccessary to install missing packages with dynamic libraries. Examplary use cases could be found below.

**Ubuntu 17.04**

<code>sudo apt-get install libgnutls28-dev libattr1-dev libglib2.0-dev libgcrypt20 libgcrypt11-dev</code>

**CENTOS 7**

<code>yum install spice-glib-devel.x86_64 libattr-devel.x86_64 libgcrypt-devel.x86_64 libgcrypt.x86_64 gnutls-devel.x86_64
</code>

Now we can continue as follows.

1. Copy the source files to your local machine.
2. Go to the directory, where you've copied the source files.
3. Now you can run the command below, and compile the file **hasher.c**.

<code>gcc -g -o hasher hasher.c `` `pkg-config --cflags --libs glib-2.0` `` -Wall -I. -lgcrypt -lgnutls</code>

4. Now you can copy the file **hasher** to the system bin directory, e.g. for Ubuntu 17.04 **/usr/local/bin** directory.
