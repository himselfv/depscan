unit depscan.MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.Menus, Depscan.Db;

type
  TMainForm = class(TForm)
    MainMenu: TMainMenu;
    File1: TMenuItem;
    miNewScan: TMenuItem;
    miOpenDb: TMenuItem;
    N1: TMenuItem;
    miExit: TMenuItem;
    SaveDialog: TSaveDialog;
    OpenDialog: TOpenDialog;
    miCloseDb: TMenuItem;
    procedure miExitClick(Sender: TObject);
    procedure miNewScanClick(Sender: TObject);
    procedure miOpenDbClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure miCloseDbClick(Sender: TObject);
    procedure FormShow(Sender: TObject);

  protected
    FDb: TDepscanDb;

  public
    procedure Refresh;

  end;


var
  MainForm: TMainForm;

implementation
uses UITypes, UniStrUtils, SystemUtils, FilenameUtils, depscan.ScanSetup, depscan.ScanProgress;

{$R *.dfm}

resourcestring
  sConfirmDbOverwrite = 'File already exists. Do you want to overwrite it?';

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  if FDb <> nil then
    FreeAndNil(FDb);
end;

procedure TMainForm.FormShow(Sender: TObject);
begin
  Refresh;
end;

procedure TMainForm.miNewScanClick(Sender: TObject);
var NewDb: TDepscanDb;
begin
  if not IsPositiveResult(ScanSetupForm.ShowModal) then
    exit;

  if not SaveDialog.Execute then exit;

  if FileExists(SaveDialog.Filename) then begin
    if MessageBox(Self.Handle, PChar(sConfirmDbOverwrite), PChar(self.Caption), MB_ICONQUESTION + MB_YESNO) <> ID_YES then
      exit;
    DeleteFile(SaveDialog.Filename);
  end;

  ScanProgressForm.Folders.Assign(ScanSetupForm.mmFolders.Lines);
  ScanProgressForm.Exts.Assign(ScanSetupForm.mmExts.Lines);
  NewDb := ScanProgressForm.ModalCreateDb(SaveDialog.Filename);
  if NewDb <> nil then begin
    if FDb <> nil then
      FreeAndNil(FDb);
    FDb := NewDb;
  end;

  Refresh;
end;

procedure TMainForm.miOpenDbClick(Sender: TObject);
var NewDb: TDepscanDb;
begin
  if not OpenDialog.Execute then exit;

  NewDb := TDepscanDb.Create(OpenDialog.Filename);

  if FDb <> nil then
    FreeAndNil(FDb);
  FDb := NewDb;

  Refresh;
end;

procedure TMainForm.miCloseDbClick(Sender: TObject);
begin
  if FDb <> nil then
    FreeAndNil(FDb);
  Refresh;
end;

procedure TMainForm.miExitClick(Sender: TObject);
begin
Close;
end;


procedure TMainForm.Refresh;
begin
  miCloseDb.Enabled := FDb <> nil;

//TODO:
end;


end.
