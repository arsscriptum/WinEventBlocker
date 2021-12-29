# DETECTION with PHANTOM 

I understand that Phantom does not kill the parent process, it is just terminating the threads. 

The issue Im seeing, and the one you can see in the video I shared, is that once you terminate all the threads belonging to a particular process, that process will itself be terminated by the OS. 

It is not an issue in Phantom per say, just that when you use it, it ends up killing the service. It's easily reproduceable, even just with Process Monitor, if you kill all the threads manually , the parent service will terminate. Hence, the preference to keep them alive with suspend.

After all, if you end up STOPPING the Event Service, why bother with the Threads ?


-------------------------------------------------------------------

1) I use my test application to LIST the EventMgr PID and Child Threads (list only).
2) In Process Explorer, I see the THREADS
3) I can log events...
4) Using PHANTOM, I terminate the threads using method 1
5) In Process Explorer, I see the THREADS BEING DEAD, but ALSO, the parent is now dead.
6) In Services, I see the Event Log Service is now DEAD

## Behavior

OBVIOUSLY, the issue here is that any user with a nose will see that the event service is down and it will be in a position to restart it. or that situation will be detected.

I get the same results with my test application that Terminates the Childs Threads. The parent service is killed.
```
    # Will list the threads
    wineventsuspend.exe -l
    # with -t argument Will Terminate them
    wineventsuspend.exe -t
    # Normale usage: suspend
    wineventsuspend.exe
````

<p align="center"><img src="https://github.com/codecastor/WinEventSuspend/blob/main/data/Bug.gif" alt="Bug" width="800"></p>


# Possible Solution

Suspending a thread causes the thread to stop executing user-mode (application) code. 

As per MSFT: This function is primarily designed for use by debuggers.  It is not used generally in algorithms, people use Terminate/Create

When the parent process code is running, it will create a thread and use it subsequently. If the thread is killed, or crashes, it will CREATE a new thread. This is straighforward and is basically a failsafe if the thread crashes.

Suspending the thread is different. Since the Parent process already has a thread created for the event creation, and that it still possesses a handle to it, and that the thread is alive. It will not CREATE a new Thread. The actual logic of the eventmgr code is not checking the thread state. It COULD do that and then resume it, but it is not. Also, one sneaky guy could execute the suspend thread code every x seconds to suspend a thread that is resumed...  Here's a video:


<p align="center"><img src="https://github.com/codecastor/WinEventSuspend/blob/main/data/Suspend.gif" alt="Suspend" width="800"></p>


## Details
 In order to avoid detection, the Event Log Service shuld not be STOPPED nor be SUSPENDED. Just the child threads.
 
 But if we:
 o) kill all the child threads ==> will terminate the parent service
 o) suspend all the child threads ==> will suspend the parent service

 So In my latest change, I have made it so that we suspend all but One threads. Bsed on my tests, I was never able to log events with the remaining active thread. And the service was also active.
