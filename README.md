# CDPSvc DLL Hijacking - From LOCAL SERVICE to SYSTEM

<p align="center">
  <img src="/demo.gif">
</p>


## Description 

For more information please visit this [blog post](https://itm4n.github.io/cdpsvc-dll-hijacking/).

/!\ __This technique works only if the target machine has less than 3.5GB of RAM__! Otherwise each service runs in a separate process and the Token Kidnapping technique is therefore useless.

## How to compile 

1) Open Visual Studio and create a new __C++ Console Application__ project.  
2) Replace the content of the main source file with the content of __cdpsgshims.cpp__.  
3) Select __Release__ and __x86__/__x64__ depending on the architecture of the target machine.  
4) Open __Project__ > __Properties__ (and make sure the selected platform - __Win32__/__x64__ - is correct)   
    - __General__ > __Configuration Type__ -> `Dynamic Library (.dll)`  
    - __C/C++__ > __Code Generation__ > __Runtime Library__ -> `Multithread (/MT)`  
5) __Build solution__  


## Usage 

1) __Rename__ the output file as __cdpsgshims.dll__.  
2) Copy it into a __PATH directory__ where you have __Write access__.  
3) __Reboot__ (or stop/start CDPSvc as an administrator).  
4) Use a tool such as `nc.exe` to __connect to the local port 1337__.  

```
C:\TOOLS\>nc64.exe 127.0.0.1 1337
[*] Searching for a SYSTEM token...
[+] SYSTEM token found.
[+] CreateProcessAsUser() OK
Microsoft Windows [version 10.0.18362.476]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt auhtority\system
```

/!\ At this point, I'd suggest to stop the service, delete the DLL and restart the service. Otherwise you won't be able to delete the file. Your shell won't die because it runs in a separate process. 
