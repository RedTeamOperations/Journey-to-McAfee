## Re-casting EDR functions

While exploring the McAfee EDR we noticed that it loads few dlls into the process during process creation. Also, we found that these loaded dlls perform the task like loading libraries, resolving function address dynamically, writing in memory etc. which we are most interested in. So instead of doing all these things from scratch we could simply hunt for those function in these dlls and reuse them.
First, we need to hunt those functions which might be useful for us. 
After reversing those dlls for a while we found the particular functions which allows us to load the library and get the function address at the same time. As we can see we can fully control those 3 parameters.

![Alt text](https://github.com/RedTeamOperations/Journey-to-McAfee/blob/main/EDR-Recasting/img/1.png?raw=true ":)")

Param_1 = Module Name <br/>
Param_2 = Function Name <br/>
Param_3 = FARPROC Pointer <br/>

So, the above function tries to get the module handle with GetModuleHandleA function if the module is already there it’ll go and call GetProcAddress if not then it’ll load the module and call the GetProcAddress function. And this is exactly what we needed and we can control all those parameters freely😊.
The above one was quite easy to control. However, this will not be the same for other functions. Few moments later we found the function which can create a user thread as well as the remote thread.
In the following function we can control param_1, param_2, and param_3 as well as Global address of RtlCreateUserThread and CreateRemoteThreadEx. <br/>

Param_1 = handle <br/>
Param_2 = thread routine/function <br/>
Param_3 = parameters for thread function <br/>

If Global variable RltCreateUserThread is not set and CreateRemoteThreadEx is set it’ll call the CreateremoteThreadEx function and vice versa. 

![Alt text](https://github.com/RedTeamOperations/Journey-to-McAfee/blob/main/EDR-Recasting/img/2.png?raw=true ":)")
![Alt text](https://github.com/RedTeamOperations/Journey-to-McAfee/blob/main/EDR-Recasting/img/3.png?raw=true ":)")
	 
Now the only thing that is remaining is to control the global variable. Since global variables remains static at some offset, we can simply add those offsets with the base address of the module. 
RtlCreateUserThread = BaseAddress of mfehcinj.dll + 0x7fb44 <br/>
CreateRemoteThreadEx = BaseAddress of mfehcinj.dll + 0x7fb50 <br/>

So, we can simply copy the function address (RtlCreateUserThread/CreateRemoteThreadEx) in those global variables. If we set global address of the function that we want to run then we also have to zero out the another one.

![Alt text](https://github.com/RedTeamOperations/Journey-to-McAfee/blob/main/EDR-Recasting/img/4.png?raw=true ":)")
 
Local Shellcode Execution.

![Alt text](https://github.com/RedTeamOperations/Journey-to-McAfee/blob/main/EDR-Recasting/img/5.png ":)")

McAfee Status

![Alt text](https://github.com/RedTeamOperations/Journey-to-McAfee/blob/main/EDR-Recasting/img/6.png ":)")

## NOTE
This is just a simple POC of utilizing the McAfee injected dll’s functions. This is specially crafted implant for McAfee environment only. It depends on a McAfee environment so analyst will have a hard time during static analysis of the binary if combined with string encryption. However, this technique has both advantages and disadvantages. 

## TODO
- [ ] **Work on Remote Injection**
- [ ] **Make payload independent to McAfee environment (dll injection !?!)**