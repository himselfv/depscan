unit depscan.MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.Menus, Depscan.Db, Vcl.ComCtrls;

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
    lbImages: TListBox;
    edtQuickfilter: TEdit;
    pcImageDetails: TPageControl;
    tsExports: TTabSheet;
    tsImports: TTabSheet;
    tsClients: TTabSheet;
    procedure miExitClick(Sender: TObject);
    procedure miNewScanClick(Sender: TObject);
    procedure miOpenDbClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure miCloseDbClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure edtQuickfilterChange(Sender: TObject);
    procedure lbImagesClick(Sender: TObject);

  protected
    FDb: TDepscanDb;
    FSelectedImage: TImageId;
    procedure ReloadImages;
    procedure ReloadDetails;
    procedure SetSelectedImage(const AValue: TImageId);
    function LbGetSelectedImage: TImageId;
    procedure LbSetSelectedImage(const AValue: TImageId);
  public
    procedure Refresh;
    property SelectedImage: TImageId read FSelectedImage write SetSelectedImage;

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
  FSelectedImage := 0;
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
  ReloadImages;
  ReloadDetails;
end;

procedure TMainForm.edtQuickfilterChange(Sender: TObject);
begin
  ReloadImages;
end;

procedure TMainForm.ReloadImages;
var AImages: TDepImageList;
  data: TDepImageData;
  oldImageId: TImageId;
begin
  oldImageId := LbGetSelectedImage;
  if FDb = nil then begin
    lbImages.Clear;
    exit;
  end;

  AImages := TDepImageList.Create;
  try
    if edtQuickFilter.Text <> '' then
      FDb.FindImages(edtQuickfilter.Text, AImages)
    else
      FDb.GetAllImages(AImages);
    lbImages.Items.BeginUpdate;
    try
      lbImages.Clear; //clear in update to prevent flicker
      for data in AImages do
        lbImages.Items.AddObject(data.name, TObject(data.id));
    finally
      lbImages.Items.EndUpdate;
    end;
  finally
    FreeAndNil(AImages);
  end;

  LbSetSelectedImage(oldImageId);
end;

procedure TMainForm.lbImagesClick(Sender: TObject);
begin
  SelectedImage := LbGetSelectedImage;
end;

function TMainForm.LbGetSelectedImage: TImageId;
begin
  if lbImages.ItemIndex < 0 then
    Result := -1
  else
    Result := TImageId(lbImages.Items.Objects[lbImages.ItemIndex]);
end;

procedure TMainForm.LbSetSelectedImage(const AValue: TImageId);
var i: integer;
begin
  for i := 0 to lbImages.Count-1 do
    if TImageId(lbImages.Items.Objects[i]) = AValue then begin
      lbImages.ItemIndex := i;
      exit;
    end;
  lbImages.ItemIndex := -1;
end;

procedure TMainForm.SetSelectedImage(const AValue: TImageId);
begin
  if FSelectedImage = AValue then exit;
  FSelectedImage := AValue;
  ReloadDetails;
end;

procedure TMainForm.ReloadDetails;
begin
  //
end;


end.
