unit depscan.ScanProgress;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Generics.Collections, PEHeaders, Depscan.Db;

type
  TExportData = record
    ord: integer;
    name: string;
  end;

  TImportData = record
    libname: string;
    ord: integer;
    name: string;
  end;
  PImportData = ^TImportData;

  TImageData = class
    id: TImageId;
    name: string;
    path: string;
    exp: array of TExportData;
    imp: array of TImportData;
  end;

  TScanProgressForm = class(TForm)
    lblProgress: TLabel;
    mmLog: TMemo;
    lbMissingImages: TListBox;
    lbMissingFunctions: TListBox;
    Label1: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);

  protected
    FFolders: TStringList;
    FExts: TStringList;
    FDb: TDepscanDb;
  public
    function ModalCreateDb(const AFilename: string): TDepscanDb;
    property Folders: TStringList read FFolders;
    property Exts: TStringList read FExts;
    property Db: TDepscanDb read FDb;

  protected
    procedure Log(const AMessage: string); overload;

  protected
    FOperation: string;
    FProgress: integer;
    FProgressMax: integer;
    procedure StartProgress(const AOperation: string; const ALength: integer = 0);
    procedure UpdateProgress;
    procedure UpdateProgressCaption;
    procedure StepProgress(const AStep: integer = 1);
    procedure EndProgress;

  protected
    FImages: TObjectList<TImageData>;
    FImage: TImageData; //current image
    FMissingImages: TStringList;
    FMissingFunctions: TStringList;
    procedure AddExport(const AOrdinal: integer; const AName: string);
    procedure AddImport(const ALibName: string; const AOrdinal: integer; const AName: string = '');

  protected
    function ImportFile(const AFilename: string): boolean;
    function ImportFile32(const hLib: PIMAGE_DOS_HEADER; const hOpt: PIMAGE_OPTIONAL_HEADER32): boolean;
    function ImportFile64(const hLib: PIMAGE_DOS_HEADER; const hOpt: PIMAGE_OPTIONAL_HEADER64): boolean;
    procedure ProcessExportDirectory(const hLib: PIMAGE_DOS_HEADER; exp: PIMAGE_EXPORT_DIRECTORY);
    procedure ResolveImports(img: TImageData);
    function ResolveImport(imp: PImportData; out idx: integer): TImageData;

  end;

var
  ScanProgressForm: TScanProgressForm;

implementation
uses UniStrUtils, FilenameUtils;

{$R *.dfm}

procedure TScanProgressForm.FormCreate(Sender: TObject);
begin
  FFolders := TStringList.Create;
  FExts := TStringList.Create;
  FImages := TObjectList<TImageData>.Create;
  FMissingImages := TStringList.Create;
  FMissingImages.Sorted := true; //hashed
  FMissingFunctions := TStringList.Create;
  FMissingFunctions.Sorted := true;
end;

procedure TScanProgressForm.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FMissingImages);
  FreeAndNil(FMissingFunctions);
  FreeAndNil(FImages);
  FreeAndNil(FExts);
  FreeAndNil(FFolders);
end;

procedure TScanProgressForm.Log(const AMessage: string);
begin
  mmLog.Lines.Add(AMessage);
end;


procedure TScanProgressForm.StartProgress(const AOperation: string; const ALength: integer = 0);
begin
  FOperation := AOperation;
  FProgress := 0;
  FProgressMax := ALength;
  UpdateProgressCaption;
end;

procedure TScanProgressForm.UpdateProgress;
begin
  lblProgress.Repaint;
end;

procedure TScanProgressForm.UpdateProgressCaption;
begin
  if FProgressMax > 0 then
    lblProgress.Caption := FOperation + ' ('+IntToStr(FProgress)+' / '+IntToStr(FProgressMax)+')'
  else
    lblProgress.Caption := FOperation;
  UpdateProgress;
end;

procedure TScanProgressForm.StepProgress(const AStep: integer = 1);
begin
  FProgress := FProgress + AStep;
  UpdateProgressCaption;
end;

procedure TScanProgressForm.EndProgress;
begin
  FOperation := '';
  FProgress := 0;
  FProgressMax := 0;
  lblProgress.Caption := '';
  UpdateProgress;
end;


function TScanProgressForm.ModalCreateDb(const AFilename: string): TDepscanDb;
var files: TFilenameArray;
  i, j: integer;
  fname: string;
begin
  FImages.Clear;
  FMissingImages.Clear;
  FMissingFunctions.Clear;

  Self.Show;
  Self.Repaint;

  if FDb <> nil then
    FreeAndNil(FDb);
  FDb := TDepscanDb.Create(AFilename);
  Db.Exec('BEGIN');

  StartProgress('Enumerating files', FFolders.Count * FExts.Count);
  SetLength(files, 0);
  for i := 0 to FFolders.Count-1 do
    for j := 0 to FExts.Count-1 do begin
      EnumAddFiles(FFolders[i]+'\'+FExts[j], true, files);
      StepProgress;
    end;

  StartProgress('Processing', Length(files));
  for fname in files do begin
    ImportFile(fname);
    StepProgress;
  end;

  StartProgress('Resolving', FImages.Count);
  for i := 0 to FImages.Count-1 do begin
    ResolveImports(FImages[i]);
    StepProgress;
  end;

  Db.Exec('COMMIT');
  StartProgress('Done');

  lbMissingImages.Items.Assign(FMissingImages);
  lbMissingFunctions.Items.Assign(FMissingFunctions);

  Self.Hide;
  Self.ShowModal;

  Result := FDb;
end;

function TScanProgressForm.ImportFile(const AFilename: string): boolean;
var hLib: HMODULE;
  header: PIMAGE_NT_HEADERS;
begin
  hLib := LoadLibraryEx(PChar(AFilename), 0, DONT_RESOLVE_DLL_REFERENCES);
  if hLib = 0 then begin
    Log(AFilename+': cannot load, error '+IntToStr(GetLastError()));
    Result := false;
    exit;
  end;
  try
    Assert(PIMAGE_DOS_HEADER(hLib).e_magic = IMAGE_DOS_SIGNATURE);
    header := PIMAGE_NT_HEADERS(PByte(hLib) + PIMAGE_DOS_HEADER(hLib).e_lfanew);
    Assert(header.Signature = IMAGE_NT_SIGNATURE);

    FImage := TImageData.Create;
    FImage.name := UniLowerCase(ExtractFilename(AFilename));
    FImage.path := UniLowerCase(ExtractFilePath(AFilename));
    FImage.id := Db.AddImage(AFilename);
    FImages.Add(FImage);

    //The base of the header is the same for 32 and 64 bit, only the OptionalHeader part is different
    if header.FileHeader.Machine = IMAGE_FILE_MACHINE_I386 then
      Result := ImportFile32(PIMAGE_DOS_HEADER(hLib), @header.OptionalHeader)
    else
    if (header.FileHeader.Machine = IMAGE_FILE_MACHINE_IA64)
    or (header.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64) then
      Result := ImportFile64(PIMAGE_DOS_HEADER(hLib), PIMAGE_OPTIONAL_HEADER64(@header.OptionalHeader))
    else begin
      Log(AFilename+': unsupported image platform');
      Result := false;
      exit;
    end;
  finally
    FreeLibrary(hLib);
  end;
end;

{$PointerMath On}

function TScanProgressForm.ImportFile32(const hLib: PIMAGE_DOS_HEADER; const hOpt: PIMAGE_OPTIONAL_HEADER32): boolean;
var
  imps: PIMAGE_IMPORT_DESCRIPTOR;
  impLibName: AnsiString;
  impThunk: PIMAGE_THUNK_DATA32;
  impName: PIMAGE_IMPORT_BY_NAME;
begin
  if hOpt.NumberOfRvaAndSizes <= 0 then begin
    Result := true;
    exit;
  end;

  if hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > 0 then
    ProcessExportDirectory(hLib, PIMAGE_EXPORT_DIRECTORY(PByte(hLib)
      + hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

  if hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress > 0 then begin
    imps := PIMAGE_IMPORT_DESCRIPTOR(PByte(hLib) + hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while imps.Name <> 0 do begin
      impLibName := PAnsiChar(PByte(hLib)+imps.Name);
      if imps.Union.OriginalFirstThunk <> 0 then
        impThunk := PIMAGE_THUNK_DATA32(PByte(hLib)+imps.Union.OriginalFirstThunk)
      else
        impThunk := PIMAGE_THUNK_DATA32(PByte(hLib)+imps.FirstThunk);

      while impThunk^.Ordinal <> 0 do begin
        if impThunk^.Ordinal and IMAGE_ORDINAL_FLAG32 = IMAGE_ORDINAL_FLAG32 then begin
          AddImport(string(impLibName), impThunk^.Ordinal and not IMAGE_ORDINAL_FLAG32, '');
        end else begin
          impName := PIMAGE_IMPORT_BY_NAME(PByte(hLib)+impThunk^.AddressOfData);
          AddImport(string(impLibName), impName.Hint, string(PAnsiChar(@impName.Name[0])));
        end;

        Inc(impThunk);
      end;

      Inc(imps);
    end;
  end;
  Result := true;
end;

function TScanProgressForm.ImportFile64(const hLib: PIMAGE_DOS_HEADER; const hOpt: PIMAGE_OPTIONAL_HEADER64): boolean;
var
  imps: PIMAGE_IMPORT_DESCRIPTOR;
  impLibName: AnsiString;
  impThunk: PIMAGE_THUNK_DATA64;
  impName: PIMAGE_IMPORT_BY_NAME;
begin
  if hOpt.NumberOfRvaAndSizes <= 0 then begin
    Result := true;
    exit;
  end;

  if hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > 0 then
    ProcessExportDirectory(hLib, PIMAGE_EXPORT_DIRECTORY(PByte(hLib)
      + hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

  if hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress > 0 then begin
    imps := PIMAGE_IMPORT_DESCRIPTOR(PByte(hLib) + hOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while imps.Name <> 0 do begin
      impLibName := PAnsiChar(PByte(hLib)+imps.Name);
      if imps.Union.OriginalFirstThunk <> 0 then
        impThunk := PIMAGE_THUNK_DATA64(PByte(hLib)+imps.Union.OriginalFirstThunk)
      else
        impThunk := PIMAGE_THUNK_DATA64(PByte(hLib)+imps.FirstThunk);

      while impThunk^.Ordinal <> 0 do begin
        if impThunk^.Ordinal and IMAGE_ORDINAL_FLAG64 = IMAGE_ORDINAL_FLAG64 then begin
          AddImport(string(impLibName), impThunk^.Ordinal and not IMAGE_ORDINAL_FLAG64, '');
        end else begin
          impName := PIMAGE_IMPORT_BY_NAME(PByte(hLib)+impThunk^.AddressOfData);
          AddImport(string(impLibName), impName.Hint, string(PAnsiChar(@impName.Name[0])));
        end;

        Inc(impThunk);
      end;

      Inc(imps);
    end;
  end;
  Result := true;
end;

//Export directory is the same in 32 and 64 bit, so the code is common
procedure TScanProgressForm.ProcessExportDirectory(const hLib: PIMAGE_DOS_HEADER; exp: PIMAGE_EXPORT_DIRECTORY);
var funcRvas: PDword;
  nameRvas: PDword;
  nameOrdinals: PWord;
  nameFound: array of boolean;
  name: PAnsiChar;
  idx: word;
  i: integer;
begin
{
Export directory consists of three tables:
1. Functions:     All exported functions. Directory.Base + Index = export ordinal.
2. Names:         All exported names.
3. NameOrdinals:  Index in Functions associated to each Name (same length as Names).
There can be multiple or no names for every functions, but always one ordinal (base + its position
in Functions).
Some entries in Functions can be nil, if that ordinal is unused.
}

  if (exp.AddressOfFunctions = 0) or (exp.NumberOfFunctions = 0) then exit; //nothing exported
  funcRvas := PDword(PByte(hLib) + exp.AddressOfFunctions);

  SetLength(nameFound, exp.NumberOfFunctions);
  for idx := 0 to Length(nameFound)-1 do
    nameFound[idx] := false;

  if exp.AddressOfNames <> 0 then begin
    //Register all names
    nameRvas := PDword(PByte(hLib) + exp.AddressOfNames);
    Assert(exp.AddressOfNameOrdinals <> 0);
    nameOrdinals := PWord(PByte(hLib) + exp.AddressOfNameOrdinals);
    for i := 0 to exp.NumberOfNames-1 do begin
      name := PAnsiChar(PByte(hLib)+nameRvas^);
      idx := (nameOrdinals+i)^;
      Assert(idx < exp.NumberOfFunctions);
      nameFound[idx] := true;
      AddExport(exp.Base + idx, string(name));
      Inc(nameRvas);
    end;
  end;

  //Register functions exported only by ordinals
  for idx := 0 to Length(nameFound)-1 do
    if ((funcRvas + idx)^ <> 0) and not nameFound[idx] then
      AddExport(exp.Base + idx, '');
end;

procedure TScanProgressForm.AddExport(const AOrdinal: integer; const AName: string);
begin
  Db.AddExport(FImage.id, AOrdinal, AName);
  SetLength(FImage.exp, Length(FImage.exp)+1);
  with FImage.exp[Length(FImage.exp)-1] do begin
    ord := AOrdinal;
    name := AName;
  end;
end;

procedure TScanProgressForm.AddImport(const ALibName: string; const AOrdinal: integer; const AName: string);
begin
  Db.AddImport(FImage.id, ALibName, AOrdinal, AName);
  SetLength(FImage.imp, Length(FImage.imp)+1);
  with FImage.imp[Length(FImage.imp)-1] do begin
    libname := UniLowerCase(ALibName);
    ord := AOrdinal;
    name := AName;
  end;
end;

procedure TScanProgressForm.ResolveImports(img: TImageData);
var i: integer;
  depImg: TImageData;
  depIdx: integer;
begin
  for i := 0 to Length(img.imp)-1 do begin
    depImg := ResolveImport(@img.imp[i], depIdx);
    if depImg = nil then begin
      if img.imp[i].name <> '' then
        Log('Cannot resolve: '+img.name+'>'+img.imp[i].name)
      else
        Log('Cannot resolve: '+img.name+'>'+IntToStr(img.imp[i].ord));
      continue;
    end;

    Db.AddLink(img.id, depImg.id, img.imp[i].ord, img.imp[i].name);
  end;
end;

function TScanProgressForm.ResolveImport(imp: PImportData; out idx: integer): TImageData;
var i, j: integer;
  img: TImageData;
  imageFound: boolean;
  sig: string;
begin
  Result := nil;
  if FMissingImages.IndexOfName(imp.libname) >= 0 then
    exit;

  if imp.name = '' then
    sig := imp.libname+'@'+IntToStr(imp.ord)
  else
    sig := imp.libname+'@'+imp.name;
  if FMissingFunctions.IndexOfName(sig) >= 0 then
    exit;

  idx := 0;
  imageFound := false;

  for i := 0 to FImages.Count-1 do begin
    img := FImages[i];
    if not SameStr(img.name, imp.libname) then
      continue;

    imageFound := true;
    if imp.name <> '' then begin
      for j := 0 to Length(img.exp)-1 do
        if SameText(img.exp[j].name, imp.name) then begin
          Result := img;
          idx := j;
          exit;
        end;
    end else begin
      for j := 0 to Length(img.exp)-1 do
        if img.exp[j].ord=imp.ord then begin
          Result := img;
          idx := j;
          exit;
        end;
    end;

  end;

  if not imageFound then
    FMissingImages.Add(imp.libname)
  else
    FMissingFunctions.Add(sig);
end;




end.
