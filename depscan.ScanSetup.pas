unit depscan.ScanSetup;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TScanSetupForm = class(TForm)
    Label1: TLabel;
    mmFolders: TMemo;
    cbRecursive: TCheckBox;
    Label2: TLabel;
    mmExts: TMemo;
    btnOk: TButton;
    Cancel: TButton;
    procedure FormShow(Sender: TObject);
  public
  end;

var
  ScanSetupForm: TScanSetupForm;

implementation
uses FilenameUtils;

{$R *.dfm}

procedure TScanSetupForm.FormShow(Sender: TObject);
begin
  mmFolders.Clear;
  mmFolders.Lines.Add(GetWindowsDir+'\System32');
end;

end.
