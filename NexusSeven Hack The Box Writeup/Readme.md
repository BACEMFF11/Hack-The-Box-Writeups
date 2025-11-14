### My Writeup for the NexusSeven challenge 

**first of all i don't evn know why this challenge is overhated , like 3.0 rating ? are we deadass rn**

Any way , whatever ppl think ; i liked it . 

The challenge combines two core vulnerabilities:

- A predictable PRNG used to generate the random suffix of the flag file.

- An unsafe file access / path traversal in the /stats/<name> endpoint that allows us escape the stats directory and read arbitrary files, including flag.txt. 


So : 
Our **goal** is to:

Reproduce the PRNG logic to predict the suffix of *_flag.txt.

Abuse the stats endpoint’s path handling to climb out of the stats directory.

Retrieve the flag via a crafted /stats/.../../../flag.txt request.

How so ? Well everything is easy after we understand that : 
The server’s life cycle for any allowed file extension (txt,html , ...):

Generate predictable random suffix.

Write stats/<rdmhex>_file.txt containing the flag.

Remove the original /file.txt

