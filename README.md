# PinCFGReconstructor

## Abstract
With the development of increasingly advanced techniques to hide the malicious 
payload of a Malware, the community of reverse engineers and security researchers
has been facing more and more complex programs which brought about the need of
more advanced analysis than classic ones based on static code inspection. To truly
understand what such malicious programs do, an analyst needs to look at them
while they are executing, thus tools to carry out their analyses at runtime have
become one of the most powerful weapons to face new threats.
Among the techniques for the design and implementation of such tools there is
dynamic binary instrumentation (DBI), an advanced solution that makes it possible
to instrument a program dynamically (i.e., while it is running), allowing for a
fine-grained inspection of its execution. Although this technique is very powerful,
it carries with it some performance and accuracy trade-offs. In this project we will
build tools to record instructions and reconstruct the control flow graph of a possibly
malicious program, discussing during the journey the challenges introduced by the
usage of DBI and proposing some solutions to mitigate these problems.

### Thanks
This work has been possible thanks to:
[Capstone](https://github.com/aquynh/capstone)
[Graphviz](https://gitlab.com/graphviz/graphviz)
