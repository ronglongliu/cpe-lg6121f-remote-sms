from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/FiberHomeSMSClient.m").read_text()
header = (ROOT / "src/FiberHomeSMSClient.h").read_text()
allowed = {"SMS_UPGRADE_MESSAGE", "SMS_GET_MESSAGE", "SMS_SEND_MESSAGE"}
for command in allowed:
    assert command in source, f"missing SMS command: {command}"
assert "NSDictionary *allowed=" in source
assert "GET_WIFI" not in source and "SET_WIFI" not in source
assert "REBOOT" not in source and "SMS_DELETE" not in source
assert "ZTE" not in source and "zte" not in source
assert "setInterval" not in source and "NSTimer" not in source
assert "fetchMessagesForDeviceAtIndex" in header
assert "sendSMS" in header
assert "delivered" in source
assert "https" in source and "willPerformHTTPRedirection" in source
print("通过：仅含短信命令白名单；无 ZTE、远程设置/重启/删除/轮询代码（静态检查）。")
