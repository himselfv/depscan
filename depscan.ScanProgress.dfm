object ScanProgressForm: TScanProgressForm
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Scan progress'
  ClientHeight = 361
  ClientWidth = 645
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poOwnerFormCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    645
    361)
  PixelsPerInch = 96
  TextHeight = 13
  object lblProgress: TLabel
    AlignWithMargins = True
    Left = 6
    Top = 6
    Width = 633
    Height = 13
    Margins.Left = 6
    Margins.Top = 6
    Margins.Right = 6
    Margins.Bottom = 6
    Align = alTop
    Caption = 'Status text'
    ExplicitLeft = 8
    ExplicitTop = 8
    ExplicitWidth = 54
  end
  object Label1: TLabel
    Left = 8
    Top = 151
    Width = 142
    Height = 13
    Caption = 'Missing images and functions:'
  end
  object mmLog: TMemo
    Left = 0
    Top = 25
    Width = 645
    Height = 89
    Align = alTop
    ReadOnly = True
    TabOrder = 0
    ExplicitTop = 29
  end
  object lbMissingImages: TListBox
    Left = 8
    Top = 170
    Width = 177
    Height = 185
    Anchors = [akLeft, akBottom]
    ItemHeight = 13
    TabOrder = 1
    ExplicitTop = 136
  end
  object lbMissingFunctions: TListBox
    Left = 191
    Top = 170
    Width = 446
    Height = 185
    Anchors = [akLeft, akBottom]
    ItemHeight = 13
    TabOrder = 2
    ExplicitTop = 136
  end
end
