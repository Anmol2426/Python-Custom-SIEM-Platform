import json
import os


OFFSET_FILE = "state/file_offsets.json"


def load_config(config_path="config/log_sources.json"):
    with open(config_path, "r") as file:
        config = json.load(file)

    return config["sources"]


def load_offsets():
    if not os.path.exists(OFFSET_FILE):
        return {}

    with open(OFFSET_FILE, "r") as file:
        return json.load(file)


def save_offsets(offsets):
    with open(OFFSET_FILE, "w") as file:
        json.dump(offsets, file)


def collect_from_file(file_path, offsets):
    logs = []

    try:
        with open(file_path, "r") as file:

            # Get last read position
            last_position = offsets.get(file_path, 0)

            # Move to last position
            file.seek(last_position)

            # Read only new lines
            new_logs = file.readlines()

            # Save new position
            offsets[file_path] = file.tell()

            logs.extend(new_logs)

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")

    return logs


def collect_logs():
    sources = load_config()
    offsets = load_offsets()

    all_logs = []

    for source in sources:

        if source["type"] == "file":
            logs = collect_from_file(source["path"], offsets)
            all_logs.extend(logs)

    save_offsets(offsets)

    return all_logs