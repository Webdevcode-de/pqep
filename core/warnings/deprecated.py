def deprecated(func):
    def wrapper(*args, **kwargs):
        import warnings
        warnings.warn(f"{func.__name__} is deprecated and will be removed in a future version.", DeprecationWarning)
        return func(*args, **kwargs)
    return wrapper