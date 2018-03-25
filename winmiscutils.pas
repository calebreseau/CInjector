unit winmiscutils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,windows,jwatlhelp32,jwawintype;

type
  TFNAPCProc = TFarProc;
  SYSTEM_HANDLE=packed record
     uIdProcess:ULONG;
     ObjectType:byte;
     Flags     :byte;
     Handle    :ushort;
     pObject   :Pointer;
     GrantedAccess:ACCESS_MASK;
  end;
  PSYSTEM_HANDLE      = ^SYSTEM_HANDLE;
  SYSTEM_HANDLE_ARRAY = Array[0..0] of SYSTEM_HANDLE;
  PSYSTEM_HANDLE_ARRAY= ^SYSTEM_HANDLE_ARRAY;
  SYSTEM_HANDLE_INFORMATION=packed record
    uCount:ULONG;
    Handles:SYSTEM_HANDLE_ARRAY;
  end;
  PSYSTEM_HANDLE_INFORMATION=^SYSTEM_HANDLE_INFORMATION;
  ntstatus=integer;

  procedure enumprocesses(output:tstringlist);
  function SetPrivilege(privilegeName: string; enable: boolean): boolean;
  function AllocMemAlign(const ASize, AAlign: Cardinal; out AHolder: Pointer): Pointer;
  function getmainthreadid(pid:dword64):dword;
  function QueueUserAPC(pfnAPC: TFNAPCProc; hThread: THandle; dwData: ULONG_PTR): DWORD; stdcall;external 'kernel32.dll' name 'QueueUserAPC';
  function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwThreadId: DWORD): THandle; external 'kernel32' name 'OpenThread';
  function getthreadinformation(hthread:thandle;thread_information_class:dword;output:pointer;size:dword):boolean;stdcall;external 'kernel32.dll' name 'GetThreadInformation';
  function setthreadinformation(hthread:thandle;thread_information_class:dword;output:pointer;size:dword):boolean;stdcall;external 'kernel32.dll' name 'setthreadinformation';
  function GetPIDbyProcessName(processName:String):integer;

implementation

function GetPIDbyProcessName(processName:String):integer;
var
  GotProcess: Boolean;
  tempHandle: tHandle;
  procE: tProcessEntry32;
begin
  tempHandle:=CreateToolHelp32SnapShot(TH32CS_SNAPALL, 0);
  procE.dwSize:=SizeOf(procE);
  GotProcess:=Process32First(tempHandle, procE);
  {$B-}
    if GotProcess and (procE.szExeFile <> processName) then
      repeat GotProcess := Process32Next(tempHandle, procE);
      until (not GotProcess) or (procE.szExeFile = processName);
  {$B+}

  if GotProcess then
    result := procE.th32ProcessID
  else
    result := 0; // process not found in running process list

  CloseHandle(tempHandle);
end;

procedure enumprocesses(output:tstringlist);
var
  Snapshot: THandle;
  pe: TProcessEntry32;
begin
  Snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
  try
    pe.dwSize := SizeOf(pe);
    if Process32First(Snapshot, pe) then
      while Process32Next(Snapshot, pe) do
        output.add(pe.szExeFile);
  finally
    CloseHandle(Snapshot);
  end;
end;


function SetPrivilege(privilegeName: string; enable: boolean): boolean;
var
    tpPrev,
    tp : TTokenPrivileges;
    token : THandle;
    dwRetLen : DWord;
begin
    result := False;
    OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, token);
    tp.PrivilegeCount := 1;
    if LookupPrivilegeValue(nil, pchar(privilegeName), tp.Privileges[0].LUID) then
    begin
        if enable then
        tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
    else
        tp.Privileges[0].Attributes := 0;
        dwRetLen := 0;
        result := AdjustTokenPrivileges(token, False, tp, SizeOf(tpPrev), tpPrev, dwRetLen);
    end;
    CloseHandle(token);
end;

function AllocMemAlign(const ASize, AAlign: Cardinal; out AHolder: Pointer): Pointer;
var
  Size: Cardinal;
  Shift: NativeUInt;
begin
  if AAlign <= 1 then
  begin
    AHolder := AllocMem(ASize);
    Result := AHolder;
    Exit;
  end;

  if ASize = 0 then
  begin
    AHolder := nil;
    Result := nil;
    Exit;
  end;

  Size := ASize + AAlign - 1;

  AHolder := AllocMem(Size);

  Shift := NativeUInt(AHolder) mod AAlign;
  if Shift = 0 then
    Result := AHolder
  else
    Result := Pointer(NativeUInt(AHolder) + (AAlign - Shift));
end;

function getmainthreadid(pid:dword64):dword;
var
  hThreadSnapshot:thandle;
  currentpid:dword;
  tentry:threadentry32;
  _tid:thandle;
  _creationtime,_exittime,_kerneltime,_usertime:windows.FILETIME;
  ctime:ularge_integer;
  _ctime:ularge_integer;
begin
   ctime.LowPart:=0;
   ctime.highPart:=0;
   ctime.quadPart:=0;
   hthreadsnapshot:=createtoolhelp32snapshot(th32CS_snapthread,pid);
   tentry.dwSize:=sizeof(threadentry32);
   result:=0;
   currentpid:=getcurrentprocessid;
   thread32first(hthreadsnapshot,tentry);
   if tentry.th32OwnerProcessID=pid then
   begin
       result:=tentry.th32ThreadID;
       exit
   end;
   while thread32next(hthreadsnapshot,tentry)=true do
   begin
     if tentry.th32OwnerProcessID=pid then
     begin
       _tid:=tentry.th32ThreadID;
       getthreadtimes(_tid,_creationtime,_exittime,_kerneltime,_usertime);
       _ctime.HighPart:=_creationtime.dwHighDateTime;
       if _ctime.HighPart>ctime.HighPart then result:=_tid;
       ctime:=_ctime;
     end;
   end;
end;

end.

