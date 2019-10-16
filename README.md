# PinCFGReconstructor

## TL;DR
An efficient Pintool to reconstruct the Control Flow Graph (CFG) of plain and UPX packed executables.

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

## Dependencies
- [Intel PIN](https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.5-97503-gac534ca30-msvc-windows.zip)
- [Capstone](https://www.capstone-engine.org/download.html)
- [Graphviz](https://www.graphviz.org/download)
- [Python 3.6.3](https://www.python.org/downloads/release/python-363)
- The solution has been compiled using Visual Studio 2010 (v100) toolset. I strongly advise to install [Visual C++ 2010 Express Edition](https://my.visualstudio.com/Downloads?q=visual%20studio%202010&wt.mc_id=o~msft~vscom~older-downloads) (to get the toolset), and then using Visual Studio 2015 or later IDE.

## Usage
Assuming Intel Pin folder is located at `C:\Pin35`, you can launch the tool with the following structure:  
`C:\Pin35\pin.exe -t C:\Pin35\icount.dll <tool-switches> -- <analyzed-program> <analyzed-program-switches>`  
By default the tool uses the Unbuffered version and generates a trace of 2Gb maximum  
Once the tool finishes instrumenting the executable it generates: a (i)`trace.out` file; a (ii)dump of each of the sections of the program; and a (iii) `report.json` file containing information about the executed programs (e.g.: Sections' low addresses and size).  
Once the analysis is finished, the CFG can be reconstructed by launching `python CFG_reconstructor.py`. A PDF of the CFG will be shown and a file called CFG.gv.pdf will be created

#### Pintool otions
Apart from the standard switches of Intel Pin, the Pintool can be configured with these additional switches:
- -**buffered**  [default false]:
        whether or not the trace is buffered
- -**thread_flushed**  [default false]:
        whether or not the trace has a thread for flushing
- -**favor_main_thread**  [default false]:
        allocate a quarter of thread buffer for threads that are not the main one
- -**tag**  [default ""]:
        tag for the performance report. If missing no report will be generated
- -**thread_buffer_size**  [default 30Mb]:
        size of the per-thread buffer
- -**trace_limit**  [default 2Gb]:
        size of the trace limit
        
### Notes
The tool has been tested on Win32 only with UPX packer.

## Thanks
This work has been possible thanks to:
[Capstone](https://github.com/aquynh/capstone)
[Graphviz](https://gitlab.com/graphviz/graphviz)
