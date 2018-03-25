unit umain;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, ComCtrls,wininjection,windows,winutils,lclintf,ntdll,winmiscutils;

type

  { Tfrmmain }

  Tfrmmain = class(TForm)
    btninject: TButton;
    btnbrowse: TButton;
    btnrefresh: TButton;
    grpinjection: TGroupBox;
    Label1: TLabel;
    Label2: TLabel;
    lblwebsite: TLabel;
    lblhelp: TLabel;
    rbqueueuserapc: TRadioButton;
    rbsetthreadcontext: TRadioButton;
    rbrtlcreateuserthread: TRadioButton;
    StatusBar1: TStatusBar;
    txtprocess: TComboBox;
    txtdll: TEdit;
    procedure btninjectClick(Sender: TObject);
    procedure btnbrowseClick(Sender: TObject);
    procedure btnrefreshClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure lblhelpClick(Sender: TObject);
    procedure lblwebsiteClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;


var
  frmmain: Tfrmmain;

implementation

{$R *.lfm}

{ Tfrmmain }


procedure Tfrmmain.btninjectClick(Sender: TObject);
var
  gprocess,gthread:thandle;
  remotepid:dword;
  injectedthread:thandle;
  injectedthreadcid:client_id;
begin
   if  SetPrivilege ('SeDebugPrivilege',true)=false then outputdebugstring(pchar('error setprivilege')) else outputdebugstring(pchar('setprivilege ok'));
    remotepid:=getpidbyprocessname(txtprocess.text);
    outputdebugstring(pchar(inttostr(remotepid)));
    gprocess:=windows.openprocess(process_all_access,false,remotepid);
    gthread:=openthread(thread_all_access,false,getmainthreadid(remotepid));
    outputdebugstring(pchar(inttostr(gthread)));
    if rbrtlcreateuserthread.checked=true then injectsys(gprocess,false,injectedthread,injectedthreadcid,txtdll.text+chr(0));
    if rbsetthreadcontext.checked=true then injectctx(gprocess,gthread,txtdll.text);
    if rbqueueuserapc.checked=true then injectapc(gprocess,gthread,txtdll.text);
    statusbar1.simpletext:='Last error: '+inttostr(getlasterror);
end;


procedure Tfrmmain.FormCreate(Sender: TObject);
begin

end;

procedure Tfrmmain.FormShow(Sender: TObject);
begin
  btnrefreshclick(sender);
  if iswindowsadmin=false then showmessage('Warning! CInjector is not elevated!');
end;

procedure Tfrmmain.lblhelpClick(Sender: TObject);
begin
  showmessage('Create remote user thread: Can load your dll in a remote process and even in a remote session. You have to use this for example to inject DLLs in system processes that are running in different sessions such a LSASS. Be careful what you inject tho, any error in system processes will make your system crash.'#13#10+
  'Change $RIP register: Will load your DLL setting the next instruction to execute in the process to load your dll.'#13#10+
  'QueueUserAPC: Same as changing RIP register but in a cleaner way, using windows APIs.'#13#10+
  'Warning: This program will only work on x64 processes and DLLs')
end;

procedure Tfrmmain.lblwebsiteClick(Sender: TObject);
begin
  openurl('https://caldevelopment.wordpress.com');
end;



procedure Tfrmmain.btnbrowseClick(Sender: TObject);
var
  dialog:topendialog;
begin
  dialog:=topendialog.create(frmmain);
  dialog.defaultext:='exe';
  if dialog.Execute=true then txtdll.text:=dialog.filename;
  dialog.Free;
end;

procedure Tfrmmain.btnrefreshClick(Sender: TObject);
var
  processes:tstringlist;
  i:integer;
begin
  processes:=tstringlist.create;
  enumprocesses(processes);
  txtprocess.Items.clear;
  for i:=0 to processes.Count-1 do txtprocess.Items.Add(processes[i]);
  processes.Free;
  if txtprocess.items.Count>0 then txtprocess.ItemIndex:=0;
end;


end.

