class WidgetRegistry:
    """
    Реєстр віджетів
    Дозволяє звертатись до віджетів за ключем в будь-якому місці програми
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(WidgetRegistry, cls).__new__(cls)
            cls._instance.registry = {}
        return cls._instance

    def register_widget(self, key, widget):
        self.registry[key] = widget

    def get_widget(self, key):
        return self.registry.get(key)


widget_registry = WidgetRegistry()
