# -*- coding: utf-8 -*-
import os
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Header, Footer, DataTable, Input, Button, Static, Label
from textual.containers import Vertical, Horizontal
from textual.reactive import var
from textual.binding import Binding
from textual.events import Key

from .i18n import t
from .ui import bytes_a_legible

# --- Pantallas Modales para Interacción ---

class ConfirmScreen(ModalScreen):
    """Pantalla modal de confirmación (Sí/No)."""
    def __init__(self, prompt: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(self.prompt, id="question"),
            Horizontal(
                Button(t("yes"), variant="primary", id="yes"),
                Button(t("no"), variant="error", id="no"),
                id="buttons",
            ),
            id="dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

class InputScreen(ModalScreen):
    """Pantalla modal para entrada de texto."""
    def __init__(self, prompt: str, initial_value: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self.prompt = prompt
        self.initial_value = initial_value

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(self.prompt),
            Input(value=self.initial_value, id="input"),
            Horizontal(
                Button(t("accept"), variant="primary", id="accept"),
                Button(t("cancel"), id="cancel"),
                id="buttons",
            ),
            id="dialog",
        )

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "accept":
            self.dismiss(self.query_one(Input).value)
        else:
            self.dismiss(None)

class FileActionScreen(ModalScreen):
    """Pantalla de acciones con navegación manual de teclado y ratón."""
    def __init__(self, file_name: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.file_name = file_name
        self.buttons = []

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label(f"Acciones para: {self.file_name}"),
            Button(t("download_file"), id="download"),
            Button(t("rename"), id="rename"),
            Button(t("delete"), id="delete", variant="error"),
            Button(t("share"), id="share"),
            Button(t("cancel"), id="cancel"),
            id="action-menu",
        )

    def on_mount(self) -> None:
        self.buttons = self.query(Button).nodes
        if self.buttons:
            self.buttons[0].focus()

    def on_key(self, event: Key) -> None:
        if not self.buttons:
            return
        
        current_focus_index = -1
        for i, button in enumerate(self.buttons):
            if button.has_focus:
                current_focus_index = i
                break
        
        if current_focus_index == -1: # Si no hay foco, enfocar el primero
            self.buttons[0].focus()
            return

        if event.key == "down":
            next_index = (current_focus_index + 1) % len(self.buttons)
            self.buttons[next_index].focus()
            event.prevent_default()
        elif event.key == "up":
            next_index = (current_focus_index - 1 + len(self.buttons)) % len(self.buttons)
            self.buttons[next_index].focus()
            event.prevent_default()

    def on_button_rolled_over(self, event) -> None:
        event.button.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id)


# --- Aplicación Principal del Explorador ---

class FileExplorerApp(App):
    CSS_PATH = "tui_v2.css"

    BINDINGS = [
        Binding("n", "create_folder", t("create_folder_short"), show=True),
        Binding("r", "rename_item", t("rename_item_short"), show=True),
        Binding("d", "delete_item", t("delete_item_short"), show=True),
        Binding("s", "share_item", t("share_item_short"), show=True),
        Binding("ctrl+r", "refresh_items", t("refresh_short"), show=True),
        Binding("backspace", "go_back", t("go_back_short"), show=True),
        Binding("q", "quit", t("quit_short"), show=True),
    ]

    current_path_str = var("/")

    def __init__(self, api_client, username, private_key, **kwargs):
        super().__init__(**kwargs)
        self.api_client = api_client
        self.username = username
        self.private_key = private_key
        self.path_stack = []
        self.current_folder_id = None
        self.items_cache = []
        self.highlighted_row_key = None

    def compose(self) -> ComposeResult:
        yield Header(name=f"{t('file_browser')} - {self.username}")
        yield Static(id="path_header")
        yield DataTable(id="file_table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("No.", key="no", width=5)
        table.add_column(t("name"), key="name", width=40)
        table.add_column(t("type"), key="type", width=10)
        table.add_column(t("size"), key="size", width=15)
        table.add_column(t("date"), key="date", width=20)
        self.action_refresh_items()
        self.call_later(table.focus)

    def on_key(self, event: Key) -> None:
        table = self.query_one(DataTable)
        if table.has_focus:
            if event.key == "down":
                table.action_cursor_down()
                event.prevent_default()
            elif event.key == "up":
                table.action_cursor_up()
                event.prevent_default()

    def watch_current_path_str(self, new_path: str) -> None:
        self.query_one("#path_header").update(f"📂 {new_path}")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.highlighted_row_key = event.row_key

    def get_selected_item_data(self):
        if self.highlighted_row_key is None:
            return None
        item_id = self.highlighted_row_key.value
        return next((item for item in self.items_cache if item['id'] == item_id), None)

    def action_refresh_items(self) -> None:
        self.highlighted_row_key = None
        response = self.api_client.obtener_arbol_archivos(self.current_folder_id)
        if response and response.status_code == 200:
            self.items_cache = response.json().get('items', [])
            self.update_table(self.items_cache)
            self.notify(t('directory_updated'))
        else:
            self.notify(t('error_getting_files'), severity="error")
            self.update_table([])

    def update_table(self, items):
        table = self.query_one(DataTable)
        table.clear()
        for i, item in enumerate(items, 1):
            icon = "📄" if item['tipo'] == 'archivo' else "📁"
            name = f"{icon} {item['nombre']}"
            size = bytes_a_legible(item.get('tamano')) if item['tipo'] == 'archivo' else ''
            date = item.get('fecha_modificacion', '')[:16]
            table.add_row(str(i), name, t(item['tipo']), size, date, key=item['id'])

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        selected_item = self.get_selected_item_data()
        if not selected_item:
            return

        if selected_item['tipo'] == 'carpeta':
            self.path_stack.append((self.current_folder_id, self.current_path_str))
            self.current_folder_id = selected_item['id']
            self.current_path_str = os.path.join(self.current_path_str, selected_item['nombre'])
            self.action_refresh_items()
        else: # Es un archivo
            def on_action_selection(action_id: str):
                if action_id == "download":
                    self.action_download_file()
                elif action_id == "rename":
                    self.action_rename_item()
                elif action_id == "delete":
                    self.action_delete_item()
                elif action_id == "share":
                    self.action_share_item()

            self.push_screen(FileActionScreen(selected_item['nombre']), on_action_selection)

    def action_go_back(self) -> None:
        if self.path_stack:
            self.current_folder_id, self.current_path_str = self.path_stack.pop()
            self.action_refresh_items()
        else:
            self.exit()

    def action_create_folder(self) -> None:
        def check_name(name: str):
            if name:
                response = self.api_client.crear_carpeta(name, self.current_folder_id)
                if response and response.status_code == 201:
                    self.notify(t('folder_created_successfully', folder_name=name))
                    self.action_refresh_items()
                else:
                    self.notify(t('error_creating_folder'), severity="error")
        self.push_screen(InputScreen(t("enter_new_folder_name")), check_name)

    def action_rename_item(self) -> None:
        item = self.get_selected_item_data()
        if not item:
            self.bell()
            return

        def check_new_name(new_name: str):
            if new_name:
                response = self.api_client.renombrar_item(item['id'], item['tipo'], new_name)
                if response and response.status_code == 200:
                    self.notify(t('item_renamed_successfully'))
                    self.action_refresh_items()
                else:
                    self.notify(t('error_renaming_item'), severity="error")
        self.push_screen(InputScreen(t("enter_new_name"), item['nombre']), check_new_name)

    def action_delete_item(self) -> None:
        item = self.get_selected_item_data()
        if not item:
            self.bell()
            return

        def confirm_delete(confirmed: bool):
            if confirmed:
                api_call = self.api_client.eliminar_archivo if item['tipo'] == 'archivo' else self.api_client.eliminar_carpeta
                response = api_call(item['id'])
                if response and response.status_code in [200, 204]:
                    self.notify(t('item_deleted_successfully'))
                    self.action_refresh_items()
                else:
                    self.notify(t('error_deleting_item'), severity="error")

        prompt = t("are_you_sure_delete_folder", folder_name=item['nombre']) if item['tipo'] == 'carpeta' else t("are_you_sure_delete_file", file_name=item['nombre'])
        self.push_screen(ConfirmScreen(prompt), confirm_delete)

    def action_download_file(self) -> None:
        item = self.get_selected_item_data()
        if not item or item['tipo'] != 'archivo':
            self.bell()
            return
        
        self.notify(f"{t('downloading_file')}: {item['nombre']}")
        
    def action_share_item(self) -> None:
        item = self.get_selected_item_data()
        if not item or item['tipo'] != 'archivo':
            self.bell()
            self.notify(t("cannot_share_folder"), severity="warning")
            return

        self.notify("Función de compartir no implementada en TUI.", severity="warning")

if __name__ == '__main__':
    class MockApiClient:
        def obtener_arbol_archivos(self, folder_id=None):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {
                        "items": [
                            {"id": "1", "nombre": "Documentos", "tipo": "carpeta", "fecha_modificacion": "2023-10-27T10:00:00Z"},
                            {"id": "2", "nombre": "reporte.pdf", "tipo": "archivo", "tamano": 1024*500, "fecha_modificacion": "2023-10-26T15:30:00Z"},
                            {"id": "3", "nombre": "fotos", "tipo": "carpeta", "fecha_modificacion": "2023-10-25T11:20:00Z"},
                        ]
                    }
            return MockResponse()
        def crear_carpeta(self, nombre, parent_id):
            class MockResponse: status_code = 201
            return MockResponse()
        def renombrar_item(self, item_id, tipo, nuevo_nombre):
            class MockResponse: status_code = 200
            return MockResponse()
        def eliminar_archivo(self, file_id):
            class MockResponse: status_code = 200
            return MockResponse()
        def eliminar_carpeta(self, folder_id):
            class MockResponse: status_code = 200
            return MockResponse()

    app = FileExplorerApp(MockApiClient(), "testuser", "dummy_key")
    app.run()
