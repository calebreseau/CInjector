# CInjector

CInjector is a x64 windows DLL injector.
It has three injection methods:

   * SetThreadContext: Writing a call to LoadLibraryA in the RIP register of the remote process so your DLL will be loaded.
   * QueueUserAPC: Same as SetThreadContext but using windows APIs
   * RtlCreateUserThread: Load your DLL in a process that is running under a different user such as system processes.



