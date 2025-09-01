def safe_tk_call(widget_attr_name):
    """
    Decorator to safely call a method only if the tkinter widget still exists.
    widget_attr_name: name of the attribute inside 'self' that holds the widget
    """
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            widget = getattr(self, widget_attr_name, None)
            try:
                if widget and widget.winfo_exists():
                    return func(self, *args, **kwargs)
            except Exception as e:
                print(f"[safe_tk_call] Skipped call due to destroyed widget: {e}")
        return wrapper
    return decorator
