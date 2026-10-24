import argparse
import json
import platform
import shutil
import uvicorn
from mj.settings import Settings


def main():
    parser = argparse.ArgumentParser(description="MJ authorized lab security platform")
    parser.add_argument("command", choices=["serve", "lab", "doctor", "token"])
    args = parser.parse_args()
    settings = Settings()
    settings.initialize()
    if args.command == "serve":
        from mj.api import create_app
        print(f"MJ dashboard: http://127.0.0.1:{settings.api_port}")
        print("Use `mj token` in a private terminal to display the operator token.")
        uvicorn.run(create_app(settings), host="127.0.0.1", port=settings.api_port, access_log=False)
    elif args.command == "lab":
        from mj.lab import create_lab
        uvicorn.run(create_lab(settings.data_dir / "lab-config.json"), host="127.0.0.1", port=settings.lab_port, access_log=False)
    elif args.command == "token":
        print(settings.token)
    else:
        print(json.dumps({"python": platform.python_version(), "ollama": shutil.which("ollama"),
                          "VBoxManage": shutil.which("VBoxManage"), "node": shutil.which("node"),
                          "model": settings.model, "dashboard_built": (settings.frontend / "index.html").exists(),
                          "vm_enabled": settings.enable_vm}, indent=2))


if __name__ == "__main__":
    main()
