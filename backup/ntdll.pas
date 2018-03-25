unit ntdll;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,windows,winmiscutils;

type
  SYSTEM_INFORMATION_CLASS = (
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemNotImplemented1,
    SystemProcessesAndThreadsInformation,
    SystemCallCounts,
    SystemConfigurationInformation,
    SystemProcessorTimes,
    SystemGlobalFlag,
    SystemNotImplemented2,
    SystemModuleInformation,
    SystemLockInformation,
    SystemNotImplemented3,
    SystemNotImplemented4,
    SystemNotImplemented5,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPagefileInformation,
    SystemInstructionEmulationCounts,
    SystemInvalidInfoClass1,
    SystemCacheInformation,
    SystemPoolTagInformation,
    SystemProcessorStatistics,
    SystemDpcInformation,
    SystemNotImplemented6,
    SystemLoadImage,
    SystemUnloadImage,
    SystemTimeAdjustment,
    SystemNotImplemented7,
    SystemNotImplemented8,
    SystemNotImplemented9,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemLoadAndCallImage,
    SystemPrioritySeparation,
    SystemNotImplemented10,
    SystemNotImplemented11,
    SystemInvalidInfoClass2,
    SystemInvalidInfoClass3,
    SystemTimeZoneInformation,
    SystemLookasideInformation,
    SystemSetTimeSlipEvent,
    SystemCreateSession,
    SystemDeleteSession,
    SystemInvalidInfoClass4,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation
    );

    client_id=record
      uniqueprocess:uint64;
      uniquethread:uint64;
    end;

    pclient_id=^client_id;

const
    STATUS_SUCCESS               = ntstatus($00000000);
    STATUS_BUFFER_OVERFLOW        = ntstatus($80000005);
    STATUS_INFO_LENGTH_MISMATCH   = ntstatus($C0000004);
    DefaulBUFFERSIZE              = $100000;

  function ntquerysysteminformation(systeminformationclass:system_information_class;systeminformation:pvoid;systeminformationlength:ulong;returnlength:pulong): ntstatus; stdcall;external 'ntdll.dll' name 'NtQuerySystemInformation';
  function ntsuspendprocess(ProcessHandle: THANDLE):boolean; stdcall;external 'ntdll.dll' name 'NtSuspendProcess';
  function NtResumeProcess(ProcessHandle: THANDLE):boolean; stdcall;external 'ntdll.dll' name 'NtResumeProcess';
  function rtlcreateuserthread(ProcessHandle: THANDLE;
     SecurityDescriptor: PSECURITY_DESCRIPTOR;
     CreateSuspended: Boolean;
     StackZeroBits: ULONG;
     StackReserved: SIZE_T; StackCommit: SIZE_T;
     StartAddress: pointer;
     StartParameter: pointer;
     ThreadHandle: PHANDLE;
     ClientID: PCLIENT_ID):ntstatus; stdcall;external 'ntdll.dll' name 'RtlCreateUserThread';
  function getsysprocesshandle(pid:dword):thandle;

implementation

function getsysprocesshandle(pid:dword):thandle;
var
  handleinfosize:ulong;
  handleinfo:psystem_handle_information;
  status:ntstatus;
  i:ulong;
  _handle:SYSTEM_HANDLE;
  _process:thandle;
  _pid:uint;
begin
   result:=0;
   handleinfosize:=$10000;
   getmem(handleinfo,handleinfosize);
   status:=ntquerysysteminformation(systemhandleinformation,handleinfo,handleinfosize,nil);
   while status=STATUS_INFO_LENGTH_MISMATCH do
   begin
     handleinfosize*=2;
     getmem(handleinfo,handleinfosize);
     status:=ntquerysysteminformation(systemhandleinformation,handleinfo,handleinfosize,nil);
   end;
   if not nt_success(status) then
   begin
        outputdebugstring(pchar('NtQuerySystemInformation failed!'));
   end;
   for i:=0 to handleinfo^.uCount-ulong(1) do
   begin
     _handle:=handleinfo^.Handles[i];
     _process:=_handle.Handle;
     GetWindowThreadProcessId(_process,_pid);
     if {(_handle.uIdProcess=getcurrentprocessid) and }(_pid=pid) then result:=_process;
   end;

end;

end.

