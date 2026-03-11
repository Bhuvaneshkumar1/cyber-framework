import os
import importlib

MODULE_DIR = "modules"

def discover_modules():

    modules = {}

    for file in os.listdir(MODULE_DIR):

        if file.endswith(".py") and file != "__init__.py":

            name = file[:-3]

            module = importlib.import_module(f"{MODULE_DIR}.{name}")

            modules[name] = module

    return modules