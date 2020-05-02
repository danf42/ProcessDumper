# ProcessDumper
Utility written in C++ to list the running processes on a Windows host, prompt user to enter a PID, and dump that particular process. 

## Background
I recently finsihed watching the videos for [Windows API Exploitation Recipes: Processes, Tokens and Memory RW](https://www.pentesteracademy.com/course?id=31) offered by [Pentester Academy](https://www.pentesteracademy.com/).  I wanted to try to expand on the process listing examples and add the ability to dump a particular process.  

## Implementation
1. Since we will be attempting to dump a process, Verify the program is running with elevated privileges and, if so, enable SeDebugPrivilege.  
2. Use CreateToolhelp32Snapshot to take a snapshot of all the running processes
3. Loop through all the processes in the snapshot displaying the parent pid, pid, and executable name of each process
4. Prompt user for PID of the process to dump
5. Attempt to open the process, if it fails, attempt to duplicate the token permissions and add to the current thread.  Try to open the process with the new permissions.  
6. Try to dump the process using MiniDumpWriteDump function

# Acknowledgments
I've left all the comments from the original example in my source code.  I found the comments to be very helpful when neededing to go back and review the functions.  
 - [Windows API Exploitation Recipes: Processes, Tokens and Memory RW](https://www.pentesteracademy.com/course?id=31) offered by [Pentester Academy](https://www.pentesteracademy.com/)
 - [Dumping LSASS without Mimikatz with MiniDumpWriteDump](https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass)

# Disclaimer
You are only authorized to use this tool on systems that you have permission to use it on. It was created for research purposes only.  The creator takes no responsibility of any mis-use of this program.
