# coffor
Forensic tools for the Coffee File System used in Contiki-NG.

The tool consist of two programs: coffee_file_extract will export data from a flash memory image containing a Coffee file system, and combinefiles.py, a python script that compares the file versions and print a similarity measure. 

## Installation

To compile, run: 
> ./configure && make 

If compiled from the github sources, please run autogen.sh to create the configure script. 

The RDEXE variable in combinefiles.py contains the full path of the radiff executable. This might have to be changed, depending on the executable location.

### Dependencies
Sodium is used for hash computations. In Ubuntu this can be installed with: 
> apt install libsodium-dev" 

Radare2's radiff is used for the file comparisons. Sources can be downloaded with: 
> git clone https://github.com/radare/radare2.git

## Usage
### coffee_file_extract

    coffee_file_extract -p <pagesize> -s <sectorsize> -l <logsize> -b <fs start> -f <filename> -v -s -d <dir> -a <hashfile>

      -p <pagesize>   The page size of the file system
      -s <sectorsize> The sector size of the file system
      -l <logsize>    The size of the log file contents 
      -b <fs start>   The offset of the start of the file system
      -f <filename>   The flash image file
      -d <dir>        The directory to store the reconstructed files
      -a <hashfile>   The file containing the sha256 hash of the files 
      -i              Invert bits if a physical dump
      -v              Verbose printing
      -s              Show some statistics
      -h, -?          Print usage
	  
### combinefiles.py

    combinefiles.py [-h] [--alg] [--target TARGET] Source [Source ...]

    Print combinations of filenames given as inputs

    positional arguments:
      Source                Source files to to compare

    optional arguments:
      -h, --help            show this help message and exit
      --alg, -s             Algorithm for comparison
      --target TARGET, -t TARGET
                            Target file for comparing the sources
