from textual.app import ComposeResult
from textual.widgets import Static, Label
from textual.reactive import reactive
from textual.containers import Vertical
from ui.constants import PIPELINE_ITEMS, PIPELINE_DESCRIPTIONS
from ui.log_queue import post_log
from agent.agent_state import AgentState
from dataclasses import replace

class ComponentView(Static):
    can_focus = True
    selected_item = reactive(0)

    def compose(self) -> ComposeResult:
        with Vertical(id = "comp_frame"):
            for pipeline_item in PIPELINE_ITEMS:
                with Vertical(classes = "comp-item-frame"):
                    yield Label(pipeline_item, classes = "comp-item")
                    yield Label(f"{PIPELINE_DESCRIPTIONS.get(pipeline_item.capitalize())}", classes = "comp-item-desc")
            yield Label("Select a component to individually toggle\nCAUTION: This may break things", id = "comp_item_hint")

    def on_mount(self) -> None:
        self.refresh_display()

    def refresh_display(self) -> None:
        state: AgentState = self.app.agent_state #type: ignore
        pipeline_frames = self.query(".comp-item-frame").results(Vertical)
        component_labels = self.query(".comp-item").results(Label)

        for i, (pipeline_frame, comp_label) in enumerate(zip(pipeline_frames, component_labels)):
            enabled = getattr(state, PIPELINE_ITEMS[i].lower())
            status = "Enabled" if enabled else "Disabled"

            pipeline_frame.remove_class("comp-item-online", "comp-item-offline", "comp-selected")

            pipeline_frame.add_class("comp-item-online" if enabled else "comp-item-offline")

            comp_label.update(f"{PIPELINE_ITEMS[i]} -> {status}")
                
            if i == self.selected_item:
                pipeline_frame.add_class("comp-selected")

            pipeline_frame.refresh()

    def watch_selected_item(self) -> None:
        self.refresh_display()

    def on_key(self, event) -> None:
        if event.key == "down":
            self.selected_item = (self.selected_item + 1) % len(PIPELINE_ITEMS)
        elif event.key == "up":
            self.selected_item = (self.selected_item - 1) % len(PIPELINE_ITEMS)
        elif event.key == "enter":
            pipeline_item = PIPELINE_ITEMS[self.selected_item].lower()
            new_state = replace(self.app.agent_state) #type: ignore
            setattr(new_state, pipeline_item, not getattr(new_state, pipeline_item))
            enabled = getattr(new_state, pipeline_item)
            post_log(f"[Settings] {pipeline_item.capitalize()} {'enabled' if enabled else 'disabled'}")
            self.app.agent_state = new_state #type: ignore
            self.refresh_display()


