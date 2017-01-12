unit depscan.Db;

interface
uses SysUtils, sqlite3;

type
  TImageId = int64;

  TDepscanDb = class
  protected
    FDb: PSQLite3;
    StmAddImage: PSQLite3Stmt;
    StmAddExport: PSQLite3Stmt;
    StmAddImport: PSQLite3Stmt;
    StmAddLink: PSQLite3Stmt;
    procedure InitDb;
    function GetLastSqliteError: string;
    procedure RaiseLastSqliteError;
  public
    constructor Create(const AFilename: string);
    destructor Destroy; override;

    function PrepareStatement(const ASql: string): PSQLite3Stmt;
    procedure Exec(const ASql: string);
    function AddImage(const AFilename: string): TImageId;
    procedure AddExport(const AImage: TImageId; const AOrdinal: integer; const AName: string);
    procedure AddImport(const AImage: TImageId; const ALibName: string; const AOrdinal: integer; const AName: string = '');
    procedure AddLink(const AImage, ADepImage: TImageId; const AOrdinal: integer; const AName: string);

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

procedure TDepscanDb.AddExport(const AImage: TImageId; const AOrdinal: integer; const AName: string);
begin
  sqlite3_bind_int64(StmAddExport, 1, AImage);
  sqlite3_bind_int64(StmAddExport, 2, AOrdinal);
  sqlite3_bind_str(StmAddExport, 3, AName);
  if sqlite3_step(StmAddExport) <> SQLITE_DONE then
    RaiseLastSQLiteError();
  sqlite3_reset(StmAddExport);
end;

procedure TDepscanDb.AddImport(const AImage: TImageId; const ALibName: string; const AOrdinal: integer; const AName: string = '');
begin
  sqlite3_bind_int64(StmAddExport, 1, AImage);
  sqlite3_bind_str(StmAddExport, 2, ALibName);
  sqlite3_bind_int64(StmAddExport, 3, AOrdinal);
  sqlite3_bind_str(StmAddExport, 4, AName);
  if sqlite3_step(StmAddExport) <> SQLITE_DONE then
    RaiseLastSQLiteError();
  sqlite3_reset(StmAddExport);
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


end.
