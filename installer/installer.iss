; Inno Setup script for Hybrid IDS.
;
; Build:
;   1. pyinstaller installer/HybridIDS.spec --clean --noconfirm
;   2. iscc installer/installer.iss
; Output: installer/output/HybridIDS-Setup-1.0.0.exe

#define MyAppName        "Hybrid IDS"
#define MyAppVersion     "1.0.0"
#define MyAppPublisher   "Unspeakable149"
#define MyAppURL         "https://github.com/Unspeakable149/Major-Project-Hybrid-Intrusion-Detection-Using-Wireshark-Packet-Analysis-and-Behavioural-Modelling-"
#define MyAppExeName     "HybridIDS.exe"

[Setup]
AppId={{F4B6C8A2-3D7E-4F1B-9C5D-8E0A2B6D9F31}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=eula.txt
OutputDir=output
OutputBaseFilename=HybridIDS-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Hybrid IDS Installer
VersionInfoProductName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; Bundle the entire PyInstaller one-folder output.
Source: "..\dist\HybridIDS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Open Dashboard in Browser"; Filename: "http://localhost:8501"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[Code]
const
  TSHARK_PATH_1 = 'C:\Program Files\Wireshark\tshark.exe';
  TSHARK_PATH_2 = 'C:\Program Files (x86)\Wireshark\tshark.exe';

function TsharkInstalled(): Boolean;
begin
  Result := FileExists(TSHARK_PATH_1) or FileExists(TSHARK_PATH_2);
end;

function InitializeSetup(): Boolean;
var
  Response: Integer;
  ErrorCode: Integer;
begin
  Result := True;
  if not TsharkInstalled() then begin
    Response := MsgBox(
      'Hybrid IDS depends on Wireshark / tshark for live packet capture, ' +
      'but it was not found on this system.' + #13#10 + #13#10 +
      'Click "Yes" to open the Wireshark download page now, or "No" to ' +
      'continue installing Hybrid IDS without Wireshark (the engine will not ' +
      'be able to capture traffic until Wireshark is installed).' + #13#10 + #13#10 +
      'Cancel exits this installer.',
      mbConfirmation, MB_YESNOCANCEL);

    case Response of
      IDYES: begin
        ShellExec('open', 'https://www.wireshark.org/download.html',
                  '', '', SW_SHOW, ewNoWait, ErrorCode);
        Result := False;
      end;
      IDNO: begin
        Result := True;
      end;
      IDCANCEL: begin
        Result := False;
      end;
    end;
  end;
end;
