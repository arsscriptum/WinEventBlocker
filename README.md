# Windows Event Thread Suspender with Automatic Privileges Escalation

This is basically the same idea as it was implemented in [Phant0m](https://github.com/hlldz/Phant0m).

Difference ? We SUSPEND the threads, instead of Terminating them. Keeping them alive.

The code can be added to a DLL, or create a service that executes the event suspend at boot. (This is what I have in my persistence toolbox).

## Why the Overkill ?

This project was mosly used to test different code block. It's not meant to be a fork of Phantom.


# NOTES

[See NOTES.md](https://github.com/codecastor/WinEventSuspend/blob/main/NOTES.md) 

______________________________________________________

### Remember that SUSPENDING THREADS will HANG PROCESSES that wants to log events.

Note that while the system won't log any events, any piece of code that actually tries to log some stuff will hang when they try to add an event. This is not an issue most of the time, but it is noticeable when the user SHUTs the computer OFF, because the OS logs that. So the shutdown procedure is very long. That's why I added a RESUME parameter that can be called before the user lgs out.

<p align="center"><img src="https://github.com/codecastor/WinEventSuspend/blob/main/data/Anim.gif" alt="Poc" width="800"></p>

