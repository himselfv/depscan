object ScanSetupForm: TScanSetupForm
  Left = 0
  Top = 0
  Caption = 'Scan setup'
  ClientHeight = 247
  ClientWidth = 378
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poOwnerFormCenter
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 0
    Top = 0
    Width = 378
    Height = 13
    Align = alTop
    Caption = 'Folders:'
    ExplicitLeft = 3
    ExplicitTop = 3
    ExplicitWidth = 39
  end
  object Label2: TLabel
    AlignWithMargins = True
    Left = 0
    Top = 128
    Width = 378
    Height = 13
    Margins.Left = 0
    Margins.Right = 0
    Margins.Bottom = 0
    Align = alTop
    Caption = 'Extensions'
    ExplicitLeft = 3
    ExplicitTop = 131
    ExplicitWidth = 52
  end
  object mmFolders: TMemo
    AlignWithMargins = True
    Left = 3
    Top = 16
    Width = 372
    Height = 89
    Align = alTop
    ScrollBars = ssVertical
    TabOrder = 0
    ExplicitLeft = 6
    ExplicitTop = 19
    ExplicitWidth = 366
  end
  object cbRecursive: TCheckBox
    Left = 0
    Top = 108
    Width = 378
    Height = 17
    Align = alTop
    Caption = 'Recursive'
    Checked = True
    State = cbChecked
    TabOrder = 1
    ExplicitLeft = 3
    ExplicitTop = 111
    ExplicitWidth = 372
  end
  object mmExts: TMemo
    AlignWithMargins = True
    Left = 3
    Top = 144
    Width = 372
    Height = 65
    Align = alTop
    Lines.Strings = (
      '*.exe'
      '*.dll'
      '*.sys'
      '*.ocx'
      '*.cpl')
    ScrollBars = ssVertical
    TabOrder = 2
    ExplicitLeft = 6
    ExplicitTop = 147
    ExplicitWidth = 366
  end
  object btnOk: TButton
    Left = 219
    Top = 215
    Width = 75
    Height = 25
    Caption = 'OK'
    Default = True
    ModalResult = 1
    TabOrder = 3
  end
  object Cancel: TButton
    Left = 300
    Top = 215
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 4
  end
end
