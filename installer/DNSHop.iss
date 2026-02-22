#define AppName "DNS Hop"
#define AppVersion "1.0.7"
#define AppPublisher "DNS Hop"
#define AppExeName "DNSHop.App.exe"
#define AppIconFile "..\src\DNSHop.App\Assets\DNSHopLogoText.ico"
#define PublishDir "..\artifacts\publish-win-x64"

[Setup]
AppId={{D54F1A90-443A-43F5-AD3F-B9FF36AC7A87}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=.\output
OutputBaseFilename=DNS-Hop-Setup-1.0.7
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile={#AppIconFile}
UninstallDisplayIcon={app}\DNSHopLogoText.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#AppIconFile}"; DestDir: "{app}"; DestName: "DNSHopLogoText.ico"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\DNSHopLogoText.ico"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\DNSHopLogoText.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
