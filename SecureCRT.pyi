# SecureCRT.pyi

class Arguments:
    def Count(self) -> int: ...
    def GetArg(self, index: int) -> str: ...

class Screen:
    def Clear(self) -> None: ...
    def Columns(self) -> int: ...
    def CurrentColumn(self) -> int: ...
    def CurrentRow(self) -> int: ...
    def Get(self, start_row: int, start_col: int, end_row: int, end_col: int) -> str: ...
    def Get2(self, start_row: int, start_col: int, end_row: int, end_col: int) -> str: ...
    def IgnoreCase(self) -> int: ...
    def IgnoreEscape(self) -> int: ...
    def MatchIndex(self) -> int: ...
    def Print(self, text: str) -> None: ...
    def ReadString(self, prompt: str) -> str: ...
    def Rows(self) -> int: ...
    def Selection(self) -> str: ...
    def Send(self, command: str) -> None: ...
    def SendSpecial(self, command: str) -> None: ...
    def Synchronous(self) -> int: ...
    def WaitForCursor(self) -> bool: ...
    def WaitForKey(self) -> bool: ...
    def WaitForString(self, string: str) -> bool: ...
    def WaitForStrings(self, strings: list[str]) -> int: ...

class Session:
    def Config(self) -> 'SessionConfiguration': ...
    def Connect(self, command: str) -> None: ...
    def ConnectInTab(self, command: str) -> 'Tab': ...
    def Connected(self) -> bool: ...
    def Disconnect(self) -> None: ...
    def Label(self) -> str: ...
    def Lock(self) -> None: ...
    def Locked(self) -> bool: ...
    def Log(self, message: str) -> None: ...
    def LogFileName(self) -> str: ...
    def LogUsingSessionOptions(self) -> None: ...
    def Logging(self) -> bool: ...
    def MonitorServerRunning(self) -> bool: ...
    def Path(self) -> str: ...
    def Print(self, text: str) -> None: ...
    def RemoteAddress(self) -> str: ...
    def RemotePort(self) -> int: ...
    def SetStatusText(self, text: str) -> None: ...
    def StartMonitorServer(self) -> None: ...
    def StopMonitorServer(self) -> None: ...
    def UnLock(self) -> None: ...
    def Unlock(self) -> None: ...

class Window:
    def Activate(self) -> None: ...
    def Active(self) -> bool: ...
    def Caption(self) -> str: ...
    def Show(self) -> None: ...
    def State(self) -> int: ...

class Dialog:
    def FileOpenDialog(self, title: str, filter: str) -> str: ...
    def FileSaveDialog(self, title: str, filter: str) -> str: ...
    def MessageBox(self, message: str, title: str, buttons: int) -> int: ...
    def Prompt(self, message: str, title: str, default: str, is_password: bool) -> str: ...

class Crt:
    ActivePrinter: str
    Arguments: Arguments
    Clipboard: 'Clipboard'
    CommandWindow: 'CommandWindow'
    Config: 'GlobalConfiguration'
    Dialog: Dialog
    FileTransfer: 'FileTransfer'
    GetActiveTab: 'Tab'
    GetLastError: int
    GetLastErrorMessage: str
    GetScriptTab: 'Tab'
    GetTab: 'Tab'
    GetTabCount: int
    OpenSessionConfiguration: 'SessionConfiguration'
    Quit: None
    Screen: Screen
    ScriptFullName: str
    Session: Session
    Sleep: None
    Synchronous: int
    Version: str
    Window: Window

# Create an instance of Crt as if it is available globally
crt = crt()