unit depscan.Db;

interface
uses SysUtils, Generics.Collections, sqlite3;

type
  TImageId = int64;
  TImageIdList = TList<TImageId>;

  TDepImageData = record
    id: TImageId;
    name: string;
    path: string;
  end;
  TDepImageList = TList<TDepImageData>;

  TDepExportData = record
    ord: integer;
    name: string;
  end;
  TDepExportList = TList<TDepExportData>;

  TDepImportData = record
    libname: string;
    ord: integer;
    name: string;
  end;
  TDepImportList = TList<TDepImportData>;

  TDepCallerData = record
    image: TImageId;
    ord: integer;
    name: string;
  end;
  TDepCallerList = TList<TDepCallerData>;

  TRowFunction = reference to procedure;

  TDepscanDb = class
  protected
    FDb: PSQLite3;
    StmAddImage: PSQLite3Stmt;
    StmAddExport: PSQLite3Stmt;
    StmAddImport: PSQLite3Stmt;
    StmAddLink: PSQLite3Stmt;
    StmGetImage: PSQLite3Stmt;
    procedure InitDb;
    function GetLastSqliteError: string;
    procedure RaiseLastSqliteError;
    procedure Query(stmt: PSQLite3Stmt; rowFunc: TRowFunction);
  public
    constructor Create(const AFilename: string);
    destructor Destroy; override;

    function PrepareStatement(const ASql: string): PSQLite3Stmt;
    procedure Exec(const ASql: string);

  protected
    procedure QueryImages(stmt: PSQLite3Stmt; AList: TDepImageList);
  public
    function AddImage(const AFilename: string): TImageId;
    function GetImageName(const AImage: TImageId): string;
    procedure GetAllImages(AList: TDepImageList);
    procedure FindImages(const AQuery: string; AList: TDepImageList);

  public
    procedure AddExport(const AImage: TImageId; const AOrdinal: integer; const AName: string);
    procedure GetExports(const AImage: TImageId; AList: TDepExportList);

    procedure AddImport(const AImage: TImageId; const ALibName: string; const AOrdinal: integer; const AName: string = '');
    procedure GetImports(const AImage: TImageId; AList: TDepImportList);

  public
    procedure AddLink(const AImage, ADepImage: TImageId; const AOrdinal: integer; const AName: string);
    procedure GetCallers(const AImage: TImageId; AList: TDepCallerList);

  end;

  ESQLiteError = class(Exception);

implementation

resourcestring
  sSqliteErrorCM = 'Error %d: %s';

constructor TDepscanDb.Create(const AFilename: string);
var res: integer;
  errText: string;
begin
  inherited Create;
  res := sqlite3_open16(PChar(AFilename), FDb);
  if res <> 0 then begin
    errText := GetLastSqliteError;
    sqlite3_close(FDb); //handle is always returned
    FDb := nil;
    raise ESQLiteError.CreateFmt(sSqliteErrorCM, [res, errText]);
  end;

  InitDb;
end;

destructor TDepscanDb.Destroy;
begin
  sqlite3_close(FDb);
  FDb := nil;
  inherited;
end;

//Retrieves text description for the last error that happened with the connection
function TDepscanDb.GetLastSqliteError: string;
begin
  Result := sqlite3_errmsg16(FDb);
end;

//Raises ESqliteError for the last error that happened with the connection
procedure TDepscanDb.RaiseLastSqliteError;
begin
  raise ESqliteError.Create(GetLastSqliteError);
end;

function TDepscanDb.PrepareStatement(const ASql: string): PSQLite3Stmt;
begin
  if sqlite3_prepare16_v2(FDb, PChar(ASql), -1, Result, nil) <> 0 then
    RaiseLastSQLiteError();
end;

//Executes an instruction or throws an error
procedure TDepscanDb.Exec(const ASql: string);
begin
  if sqlite3_exec(FDb, PAnsiChar(Utf8String(ASql)), nil, nil, nil) <> 0 then
    RaiseLastSqliteError();
end;

function sqlite3_bind_str(pStmt: PSQLite3Stmt; i: Integer; const zData: string): integer;
begin
  Result := sqlite3_bind_text16(pStmt, i, PChar(zData), -1, nil);
end;


procedure TDepscanDb.InitDb;
begin
  Exec('PRAGMA cache_size=200000');
  Exec('PRAGMA synchronous=OFF');
  Exec('PRAGMA count_changes=OFF');
  Exec('PRAGMA temp_store=2');

  Exec('CREATE TABLE IF NOT EXISTS images ('
    +'id INTEGER PRIMARY KEY,'
    +'name TEXT NOT NULL COLLATE NOCASE,'
    +'path TEXT COLLATE NOCASE'
    +')');

  Exec('CREATE TABLE IF NOT EXISTS exports ('
    +'image INTEGER NOT NULL,'
    +'ordinal INTEGER NOT NULL,'
    +'name TEXT COLLATE NOCASE'
    +')');

  Exec('CREATE TABLE IF NOT EXISTS imports ('
    +'image INTEGER NOT NULL,'
    +'libname TEXT COLLATE NOCASE,'
    +'ordinal INTEGER NOT NULL,'
    +'name TEXT COLLATE NOCASE'
    +')');

  Exec('CREATE TABLE IF NOT EXISTS links ('
    +'image INTEGER NOT NULL,'
    +'depimage INTEGER NOT NULL,'
    +'ordinal TEXT COLLATE NOCASE,'
    +'name TEXT COLLATE NOCASE'
    +')');

  StmAddImage := PrepareStatement('INSERT INTO images (name,path) VALUES (?,?)');
  StmAddExport := PrepareStatement('INSERT INTO exports (image,ordinal,name) VALUES (?,?,?)');
  StmAddImport := PrepareStatement('INSERT INTO imports (image,ordinal,name) VALUES (?,?,?)');
  StmAddLink := PrepareStatement('INSERT INTO links (image,depimage,ordinal,name) VALUES (?,?,?,?)');
  StmGetImage := PrepareStatement('SELECT * FROM images WHERE id=?');
end;

function TDepscanDb.AddImage(const AFilename: string): TImageId;
begin
  sqlite3_bind_str(StmAddImage, 1, ExtractFilename(AFilename));
  sqlite3_bind_str(StmAddImage, 2, ExtractFilePath(AFilename));
  if sqlite3_step(StmAddImage) <> SQLITE_DONE then
    RaiseLastSQLiteError();
  sqlite3_reset(StmAddImage);
  Result := sqlite3_last_insert_rowid(FDb);
end;

function TDepScanDb.GetImageName(const AImage: TImageId): string;
begin
  sqlite3_bind_int64(StmGetImage, 1, AImage);
  if sqlite3_step(StmGetImage) <> SQLITE_ROW then
    RaiseLastSQLiteError();
  Result := sqlite3_column_text16(StmGetImage, 1);
  sqlite3_reset(StmGetImage);
end;


procedure TDepscanDb.Query(stmt: PSQLite3Stmt; rowFunc: TRowFunction);
var res: integer;
begin
  res := sqlite3_step(stmt);
  while res = SQLITE_ROW do begin
    rowFunc();
    res := sqlite3_step(stmt);
  end;
  if res <> SQLITE_DONE then
    RaiseLastSQLiteError;
  sqlite3_finalize(stmt); //"reset", if reusing
end;

procedure TDepscanDb.QueryImages(stmt: PSQLite3Stmt; AList: TDepImageList);
var data: TDepImageData;
begin
  Query(stmt, procedure begin
    data.id := sqlite3_column_int64(stmt, 0);
    data.name := sqlite3_column_text16(stmt, 1);
    data.path := sqlite3_column_text16(stmt, 2);
    AList.Add(data);
  end);
end;

procedure TDepscanDb.GetAllImages(AList: TDepImageList);
var stmt: PSQLite3Stmt;
begin
  stmt := PrepareStatement('SELECT * FROM images');
  QueryImages(stmt, AList);
end;

procedure TDepscanDb.FindImages(const AQuery: string; AList: TDepImageList);
var stmt: PSQLite3Stmt;
begin
  stmt := PrepareStatement('SELECT * FROM images WHERE name LIKE ?');
  sqlite3_bind_str(stmt, 1, '%'+AQuery+'%');
  QueryImages(stmt, AList);
end;

procedure TDepscanDb.AddExport(const AImage: TImageId; const AOrdinal: integer; const AName: string);
begin
  sqlite3_bind_int64(StmAddExport, 1, AImage);
  sqlite3_bind_int64(StmAddExport, 2, AOrdinal);
  sqlite3_bind_str(StmAddExport, 3, AName);
  if sqlite3_step(StmAddExport) <> SQLITE_DONE then
    RaiseLastSQLiteError();
  sqlite3_reset(StmAddExport);
end;

procedure TDepscanDb.GetExports(const AImage: TImageId; AList: TDepExportList);
var stmt: PSQLite3Stmt;
  data: TDepExportData;
begin
  stmt := PrepareStatement('SELECT * FROM exports WHERE image=?');
  sqlite3_bind_int64(stmt, 1, AImage);
  Query(stmt, procedure begin
    data.ord := sqlite3_column_int64(stmt, 1);
    data.name := sqlite3_column_text16(stmt, 2);
    AList.Add(data);
  end);
end;

procedure TDepscanDb.AddImport(const AImage: TImageId; const ALibName: string; const AOrdinal: integer; const AName: string = '');
begin
  sqlite3_bind_int64(StmAddImport, 1, AImage);
  sqlite3_bind_str(StmAddImport, 2, ALibName);
  sqlite3_bind_int64(StmAddImport, 3, AOrdinal);
  sqlite3_bind_str(StmAddImport, 4, AName);
  if sqlite3_step(StmAddImport) <> SQLITE_DONE then
    RaiseLastSQLiteError();
  sqlite3_reset(StmAddImport);
end;

procedure TDepscanDb.GetImports(const AImage: TImageId; AList: TDepImportList);
var stmt: PSQLite3Stmt;
  data: TDepImportData;
begin
  stmt := PrepareStatement('SELECT * FROM imports WHERE image=?');
  sqlite3_bind_int64(stmt, 1, AImage);
  Query(stmt, procedure begin
    data.libname := sqlite3_column_text16(stmt, 1);
    data.ord := sqlite3_column_int64(stmt, 2);
    data.name := sqlite3_column_text16(stmt, 3);
    AList.Add(data);
  end);
end;

procedure TDepscanDb.AddLink(const AImage, ADepImage: TImageId; const AOrdinal: integer; const AName: string);
begin
  sqlite3_bind_int64(StmAddLink, 1, AImage);
  sqlite3_bind_int64(StmAddLink, 2, ADepImage);
  sqlite3_bind_int64(StmAddLink, 3, AOrdinal);
  sqlite3_bind_str(StmAddLink, 4, AName);
  if sqlite3_step(StmAddLink) <> SQLITE_DONE then
    RaiseLastSQLiteError();
  sqlite3_reset(StmAddLink);
end;

procedure TDepscanDb.GetCallers(const AImage: TImageId; AList: TDepCallerList);
var stmt: PSQLite3Stmt;
  data: TDepCallerData;
begin
  stmt := PrepareStatement('SELECT image, ordinal, name FROM links WHERE depimage=?');
  sqlite3_bind_int64(stmt, 1, AImage);
  Query(stmt, procedure begin
    data.image := sqlite3_column_int64(stmt, 0);
    data.ord := sqlite3_column_int64(stmt, 1);
    data.name := sqlite3_column_text16(stmt, 2);
    AList.Add(data);
  end);
end;



end.
