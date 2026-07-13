from dataclasses import dataclass

# always replace this with dataclasses.replace() and reassign.
# Textual's reactive watcher won't trigger when mutating a field in place.
@dataclass()
class AgentState:
    collector: bool = False
    parser: bool = False
    detector: bool = False
    maintenance: bool = False
