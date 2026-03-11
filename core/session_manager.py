session = {
    "target": None,
    "module": None
}

def set_target(target):
    session["target"] = target

def get_target():
    return session["target"]

def set_module(module):
    session["module"] = module

def get_module():
    return session["module"]