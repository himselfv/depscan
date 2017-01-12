program depscan;

uses
  Vcl.Forms,
  depscan.MainForm in 'depscan.MainForm.pas' {MainForm},
  PEHeaders in 'PEHeaders.pas',
  depscan.ScanSetup in 'depscan.ScanSetup.pas' {ScanSetupForm},
  depscan.ScanProgress in 'depscan.ScanProgress.pas' {ScanProgressForm},
  depscan.Db in 'depscan.Db.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.CreateForm(TScanSetupForm, ScanSetupForm);
  Application.CreateForm(TScanProgressForm, ScanProgressForm);
  Application.Run;
end.
