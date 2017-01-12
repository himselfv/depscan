object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'MainForm'
  ClientHeight = 393
  ClientWidth = 784
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Padding.Left = 3
  Padding.Top = 3
  Padding.Right = 3
  Padding.Bottom = 3
  Menu = MainMenu
  OldCreateOrder = False
  OnDestroy = FormDestroy
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object MainMenu: TMainMenu
    Left = 16
    Top = 16
    object File1: TMenuItem
      Caption = 'File'
      object miNewScan: TMenuItem
        Caption = 'New...'
        OnClick = miNewScanClick
      end
      object miOpenDb: TMenuItem
        Caption = 'Open...'
        OnClick = miOpenDbClick
      end
      object miCloseDb: TMenuItem
        Caption = 'Close'
        OnClick = miCloseDbClick
      end
      object N1: TMenuItem
        Caption = '-'
      end
      object miExit: TMenuItem
        Caption = 'Exit'
        OnClick = miExitClick
      end
    end
  end
  object SaveDialog: TSaveDialog
    DefaultExt = '*.db'
    Filter = 'Databases (*.db)|*.db|All Files (*.*)|*.*'
    Title = 'Save database as...'
    Left = 136
    Top = 16
  end
  object OpenDialog: TOpenDialog
    DefaultExt = '*.db'
    Filter = 'Databases (*.db)|*.db|All Files (*.*)|*.*'
    Title = 'Open dependency database'
    Left = 72
    Top = 16
  end
end
