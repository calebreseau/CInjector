unit wininjection;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,jwatlhelp32,jwawintype,windows,dialogs,ntdll,winmiscutils;


  function injectsys(ahandle:thandle;susp:boolean;th:thandle;ch:client_id;dll:string):dword;
  function injectctx(hprocess, hthread: thandle; dll: string): boolean;
  function injectapc( hprocess,hthread:thandle;dll:string):boolean;


implementation



function injectapc( hprocess,hthread:thandle;dll:string):boolean;
var
lpDllAddr,lploadLibraryAddr:pointer;
byteswritten:nativeuint;
begin
//memory address for dll
lpDllAddr := VirtualAllocEx(hProcess, nil, length(dll), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProcess, lpDllAddr, @dll[1], length(dll), byteswritten); // write dll path
if byteswritten =0 then exit;
OutputDebugString(pchar('lpDllAddr:'+inttohex(nativeuint(lpDllAddr),8)+' '+inttostr(byteswritten )+' written'));
//memory address of loadlibrary
lploadLibraryAddr := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
OutputDebugString(pchar('loadLibraryAddress:'+inttohex(nativeuint(lploadLibraryAddr),8)));
//
if QueueUserAPC(GetProcAddress(LoadLibraryA('kernel32.dll'), 'LoadLibraryA'), hThread, nativeuint(lpDllAddr))=0
   then result:=false
   else result:=true;

end;

function injectctx(hprocess, hthread: thandle; dll: string): boolean;
const
  codeX64_2:array [0..62] of byte =
    // sub rsp, 28h
    ($48, $83, $ec, $28,
    // mov [rsp + 18], rax
    $48, $89, $44, $24, $18,
    // mov [rsp + 10h], rcx
    $48, $89, $4c, $24, $10,
    // mov rcx, 11111111111111111h  -> DLL
    $48, $b9, $11, $11, $11, $11, $11, $11, $11, $11,
    // mov rax, 22222222222222222h  -> Loadlibrary
    $48, $b8, $22, $22, $22, $22, $22, $22, $22, $22,
    // call rax
    $ff, $d0,
    // mov rcx, [rsp + 10h]
    $48, $8b, $4c, $24, $10,
    // mov rax, [rsp + 18h]
    $48, $8b, $44, $24, $18,
    // add rsp, 28h
    $48, $83, $c4, $28,
    // mov r11, 333333333333333333h  -> RIP
    $49, $bb, $33, $33, $33, $33, $33, $33, $33, $33,
    // jmp r11
    $41, $ff, $e3);
var
  lpDllAddr, stub, lploadLibraryAddr: pointer;
   dwdlladdr, dwloadlibraryaddr: nativeuint;
  oldip,byteswritten: nativeuint;
  l,h:dword;
  ctx: PContext;
  Storage: Pointer;
  i:byte;
  tmp:string;
begin
  result:=true;
  if ntsuspendprocess(hprocess)=false then outputdebugstring(pchar('suspend failed: '+inttostr(getlasterror)));
  //memory address for dll
  lpDllAddr := VirtualAllocEx(hProcess, nil, length(dll), MEM_COMMIT, PAGE_READWRITE);
  if lpDllAddr = nil then
  begin
       outputdebugstring(pchar('lpDllAddr is null:'+inttostr(getlasterror)));
  end;
  WriteProcessMemory(hProcess, lpDllAddr, @dll[1], length(dll), byteswritten);
  // write dll path
  if byteswritten <> length(dll) then
  begin
     outputdebugstring(pchar('WriteProcessMemory failed'));
  end;

  if byteswritten = 0 then exit;
  dwdlladdr := nativeuint(lpDllAddr);
  OutputDebugString(PChar('lpDllAddr:' + inttohex(nativeuint(lpDllAddr), 8)));
  //memory address of code
  stub := VirtualAllocEx(hProcess, nil, length(codeX64_2 ), MEM_COMMIT,PAGE_EXECUTE_READWRITE);
  if stub = nil then
  begin
       outputdebugstring(pchar('stub is null'));
       result:=false;
  end;
  OutputDebugString(PChar('stub:' + inttohex(nativeuint(stub), 8)));
  //memory address of loadlibrary
  lploadLibraryAddr := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
  dwloadlibraryaddr := nativeuint(lploadLibraryAddr);
  OutputDebugString(PChar('loadLibraryAddress:' + inttohex( nativeuint(lploadLibraryAddr), 8)));
  ctx := AllocMemAlign(SizeOf(TContext), 16, Storage);
  ctx^.ContextFlags := CONTEXT_CONTROL;
  //
  if GetThreadContext(hThread, ctx^)=false then
  begin
       outputdebugstring(pchar('GetThreadContext failed:'+inttostr(getlasterror)));
       result:=false;
  end;
  oldIP := ctx^.Rip;
  OutputDebugString(PChar('oldip:' + inttohex(nativeuint(oldip), 8)));
  //RIP
  copymemory(@codeX64_2 [$34], @oldip, sizeof(nativeuint));
  //dwdlladdr
  copymemory(@codeX64_2 [$10], @dwdlladdr, sizeof(nativeuint));
  //dwloadlibraryaddr
  copymemory(@codeX64_2 [$1a], @dwloadlibraryaddr, sizeof(nativeuint));
  WriteProcessMemory(hProcess, stub, @codeX64_2[0], length(codeX64_2 ), byteswritten);
  if byteswritten<>length(codeX64_2 ) then
  begin
     outputdebugstring(pchar('WriteProcessMemory failed'));
     result:=false
  end;
  // write code
  if byteswritten = 0 then exit;
  ctx^.rip := nativeuint(stub);
  if SetThreadContext(hThread, ctx^)=false then
  begin
   outputdebugstring(pchar('SetThreadContext failed:'+inttostr(getlasterror)));
   result:=false;
  end;
   for i:=0 to length(codeX64_2 )-1 do tmp:=tmp+ (inttohex(codeX64_2[i],2)+' ');
   if ntresumeprocess(hprocess)=false then
   begin
     outputdebugstring(pchar('resume failed: '+inttostr(getlasterror)));
     result:=false;
   end;
  end;

function injectsys(ahandle:thandle;susp:boolean;th:thandle;ch:client_id;dll:string):dword;
var
	alloc:POINTER;
        byteswritten:ptruint;
        last:boolean;
        loadlibrarypointer:pointer;
        size:qword;
        status:int64;
        //buf:ansistring;
begin
     result:=0;
        status:=0;
        size:=length(dll)+sizeof(char);
	last:=setprivilege('sedebugprivilege',true);
        if last=false then outputdebugstring(pchar('error setprivilege'));
	loadlibrarypointer:=getprocaddress(getmodulehandle('kernel32.dll'),'LoadLibraryA');
        alloc:=nil;
        alloc:=VirtualAllocEx(ahandle, nil, size, MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if alloc=nil
                    then outputdebugstring(pchar('VirtualAllocEx failed: '+inttostr(getlasterror)))
                    else outputdebugstring(pchar('VirtualAllocEx:'+inttohex(dword(alloc),8)));
        last:=writeprocessmemory(ahandle,alloc,@dll[1],size,byteswritten);
        if last=false then outputdebugstring(pchar('error wpm'));
	status:=rtlcreateuserthread(ahandle,nil,susp,0,0,0,loadlibrarypointer,alloc,@th,@ch);
        if status<>0 then showmessage('error injecting: '+inttohex(status,8))
        else showmessage('inject ok');
end;



end.

