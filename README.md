# CInjector

CInjector is a x64 windows DLL injector.
It has three injection methods:

   * SetThreadContext: Writing a call to LoadLibraryA in the RIP register of the remote process main thread so your DLL will be loaded.
   * QueueUserAPC: Same as SetThreadContext but using APC
   * RtlCreateUserThread: Load your DLL in a process that is running under a different user such as system processes.


A lot of the functions used here have been written using the help of erwan.labalec.fr

Site webpage: https://caldevelopment.wordpress.com/cinjector/
