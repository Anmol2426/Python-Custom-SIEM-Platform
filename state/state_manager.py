import json
import os

STATE_FILE = "state/detection_state.json"


class StateManager:
    def __init__(self):
        self.state = {}
        self._load_state()

    def _load_state(self):
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r") as f:
                    self.state = json.load(f)
            except Exception:
                self.state = {}
        else:
            self.state = {}

    def save_state(self):
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(self.state, f)
        except Exception as e:
            print(f"[StateManager] Error saving state: {e}")

    def get_rule_state(self, rule_name):
        return self.state.get(rule_name, {})

    def set_rule_state(self, rule_name, data):
        self.state[rule_name] = data