# coffor
Forensic tools for the Coffee File System used in Contiki-NG.

The tool consist of two programs: coffee_file_extract will export data from a flash memory image containing a Coffee file system, and combinefiles.py, a pythonscript that compares the file versions and print a similarity measure. 

## Installation

To compile, run ./configure and make. 

If compiled from the github sources, please run autogen.sh to create the configure script. 

### Dependencies
Sodium is used for hash computations. In Ubuntu this can be installed with: "apt install libsodium-dev" 

Radare2's radiff is used for the file comparisons. Sources can be downloaded with: "git clone https://github.com/radare/radare2.git"

q
