object ScanProgressForm: TScanProgressForm
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Scan progress'
  ClientHeight = 118
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
  PixelsPerInch = 96
  TextHeight = 13
  object lblProgress: TLabel
    Left = 8
    Top = 8
    Width = 54
    Height = 13
    Caption = 'Status text'
  end
  object mmLog: TMemo
    Left = 0
    Top = 29
    Width = 645
    Height = 89
    Align = alBottom
    ReadOnly = True
    TabOrder = 0
    ExplicitLeft = 8
    ExplicitTop = 530
    ExplicitWidth = 635
  end
end
