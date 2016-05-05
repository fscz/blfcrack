# blfcrack
a dictionary-based password cracker

### dictionaries
dictionaries are text files with one password on each line

### password files
password files are files such as /etc/master.passwd 
see https://www.freebsd.org/cgi/man.cgi?query=master.passwd&sektion=5

### building 
requires gmake

    make

### tested on 
- openbsd
- osx

### usage
    blfcrack -d dictionary_file -p master.passwd


