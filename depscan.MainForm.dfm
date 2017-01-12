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
  Menu = MainMenu
  OldCreateOrder = False
  OnDestroy = FormDestroy
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object lbImages: TListBox
    Left = 0
    Top = 21
    Width = 217
    Height = 372
    Align = alLeft
    ItemHeight = 13
    TabOrder = 1
    OnClick = lbImagesClick
  end
  object edtQuickfilter: TEdit
    Left = 0
    Top = 0
    Width = 784
    Height = 21
    Align = alTop
    TabOrder = 0
    TextHint = 'Quick Filter'
    OnChange = edtQuickfilterChange
    ExplicitLeft = 24
    ExplicitTop = 144
    ExplicitWidth = 121
  end
  object pcImageDetails: TPageControl
    Left = 217
    Top = 21
    Width = 567
    Height = 372
    ActivePage = tsExports
    Align = alClient
    TabOrder = 2
    object tsExports: TTabSheet
      Caption = 'Exports'
      ExplicitWidth = 281
      ExplicitHeight = 165
    end
    object tsImports: TTabSheet
      Caption = 'Imports'
      ImageIndex = 1
      ExplicitWidth = 281
      ExplicitHeight = 165
    end
    object tsClients: TTabSheet
      Caption = 'Clients'
      ImageIndex = 2
      ExplicitWidth = 281
      ExplicitHeight = 165
    end
  end
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
